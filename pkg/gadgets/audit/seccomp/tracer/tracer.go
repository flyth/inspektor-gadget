// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type event -cc clang auditseccomp ./bpf/audit-seccomp.c -- -I./bpf/ -I../../../../ -I../../../../${TARGET} -D__KERNEL__
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type event -cc clang auditseccompwithfilters ./bpf/audit-seccomp.c -- -DWITH_FILTER=1 -I./bpf/ -I../../../../ -I../../../../${TARGET} -D__KERNEL__

const (
	BPFProgName = "ig_audit_secc"
	BPFMapName  = "events"
)

type Tracer struct {
	config        *Config
	eventCallback func(types.Event)

	collection *ebpf.Collection
	eventMap   *ebpf.Map
	reader     *perf.Reader

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
}

type Config struct {
	ContainersMap *ebpf.Map
	MountnsMap    *ebpf.Map
}

func NewTracer(config *Config, eventCallback func(types.Event)) (*Tracer, error) {
	var err error
	var spec *ebpf.CollectionSpec

	if config.MountnsMap == nil {
		spec, err = loadAuditseccomp()
	} else {
		spec, err = loadAuditseccompwithfilters()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}

	if config.MountnsMap != nil {
		mapReplacements["mount_ns_filter"] = config.MountnsMap
	}
	if config.ContainersMap != nil {
		mapReplacements["containers"] = config.ContainersMap
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	rd, err := perf.NewReader(coll.Maps[BPFMapName], gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t := &Tracer{
		config:        config,
		eventCallback: eventCallback,
		collection:    coll,
		eventMap:      coll.Maps[BPFMapName],
		reader:        rd,
	}

	kprobeProg, ok := coll.Programs[BPFProgName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPFProgName)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", kprobeProg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to attach kprobe: %w", err)
	}

	go t.run()

	return t, nil
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		eventC := (*auditseccompEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				CommonData: eventtypes.CommonData{
					// Get 'Namespace', 'Pod' and 'Container' from
					// BPF and not from the gadget helpers  because the
					// container might be terminated immediately
					// after the BPF kprobe on audit_seccomp() is
					// executed (e.g. with SCMP_ACT_KILL), so by
					// the time the event is read from the perf
					// ring buffer, we might not be able to get the
					// Kubernetes metadata from the mount namespace
					// id.
					Namespace: gadgets.FromCString(eventC.Container.Namespace[:]),
					Pod:       gadgets.FromCString(eventC.Container.Pod[:]),
					Container: gadgets.FromCString(eventC.Container.Container[:]),
				},
			},
			Pid:       uint32(eventC.Pid),
			MountNsID: uint64(eventC.MntnsId),
			Syscall:   syscallToName(int(eventC.Syscall)),
			Code:      codeToName(uint(eventC.Code)),
			Comm:      gadgets.FromCString(eventC.Comm[:]),
		}

		t.eventCallback(event)
	}
}

func (t *Tracer) Close() {
	t.reader.Close()
	t.progLink = gadgets.CloseLink(t.progLink)
	t.collection.Close()
}
