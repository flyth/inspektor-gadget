// Copyright 2022 The Inspektor Gadget authors
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
	"fmt"
	"syscall"
	"unsafe"

	"github.com/google/gopacket/layers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdump/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type Config struct {
	FilterString string
	SnapLen      int
}

type link struct {
	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	program []bpf.RawInstruction

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link
}

func NewTracer(config *Config) (*Tracer, error) {
	t := &Tracer{
		attachments: map[string]*link{},
	}

	ins, err := TcpdumpExprToBPF(config.FilterString, layers.LinkTypeEthernet, config.SnapLen)
	if err != nil {
		return nil, fmt.Errorf("failed to compile tcpdump expression to bpf")
	}

	t.program, err = bpf.Assemble(ins)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble bpf program: %w", err)
	}

	return t, nil
}

func (t *Tracer) releaseLink(key string, l *link) {
	unix.Close(l.sockFd)
	delete(t.attachments, key)
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
	eventCallback func(types.Event),
) (err error) {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	l := &link{
		users:  1,
		sockFd: -1,
	}
	defer func() {
		if err != nil {
			if l.sockFd != -1 {
				unix.Close(l.sockFd)
			}
		}
	}()

	sockFd, err := rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	l.sockFd = sockFd

	err = syscall.SetNonblock(l.sockFd, false)
	if err != nil {
		return fmt.Errorf("failed to set socket to non-blocking: %w", err)
	}

	if err := unix.SetsockoptSockFprog(l.sockFd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &unix.SockFprog{
		Len:    uint16(len(t.program)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&t.program[0])),
	}); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	t.attachments[key] = l

	go t.run(l, eventCallback)

	return nil
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.attachments[key]; ok {
		l.users--
		if l.users == 0 {
			t.releaseLink(key, l)
		}
		return nil
	} else {
		return fmt.Errorf("key not attached: %q", key)
	}
}

func (t *Tracer) run(
	l *link,
	eventCallback func(types.Event),
) {
	for {
		b := make([]byte, 3000)
		n, _, err := syscall.Recvfrom(l.sockFd, b, 0)
		if err != nil {
			return
		}
		eventCallback(types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Payload: b[:n],
		})
	}
}
