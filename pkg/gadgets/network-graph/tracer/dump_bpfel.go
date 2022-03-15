// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type dumpGraphKeyT struct {
	ContainerQuark uint64
	PktType        uint32
	Ip             uint32
	Proto          uint16
	Port           uint16
	_              [4]byte
}

// loadDump returns the embedded CollectionSpec for dump.
func loadDump() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DumpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load dump: %w", err)
	}

	return spec, err
}

// loadDumpObjects loads dump and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *dumpObjects
//     *dumpPrograms
//     *dumpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDumpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDump()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dumpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dumpSpecs struct {
	dumpProgramSpecs
	dumpMapSpecs
}

// dumpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dumpProgramSpecs struct {
	DumpGraph *ebpf.ProgramSpec `ebpf:"dump_graph"`
}

// dumpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dumpMapSpecs struct {
	Graphmap *ebpf.MapSpec `ebpf:"graphmap"`
}

// dumpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDumpObjects or ebpf.CollectionSpec.LoadAndAssign.
type dumpObjects struct {
	dumpPrograms
	dumpMaps
}

func (o *dumpObjects) Close() error {
	return _DumpClose(
		&o.dumpPrograms,
		&o.dumpMaps,
	)
}

// dumpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDumpObjects or ebpf.CollectionSpec.LoadAndAssign.
type dumpMaps struct {
	Graphmap *ebpf.Map `ebpf:"graphmap"`
}

func (m *dumpMaps) Close() error {
	return _DumpClose(
		m.Graphmap,
	)
}

// dumpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDumpObjects or ebpf.CollectionSpec.LoadAndAssign.
type dumpPrograms struct {
	DumpGraph *ebpf.Program `ebpf:"dump_graph"`
}

func (p *dumpPrograms) Close() error {
	return _DumpClose(
		p.DumpGraph,
	)
}

func _DumpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed dump_bpfel.o
var _DumpBytes []byte
