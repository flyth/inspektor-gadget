// Copyright 2023 The Inspektor Gadget authors
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

package prombtf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

const (
	MetricsMapName = "metrics_map"
)

var ErrUnsupported = errors.New("bpf program doesn't support metrics")

type CollectorData struct {
	collector *Collector
	key       []byte
	values    []byte
}

// Collector analyzes an ebpf program and extracts metric collection maps and auto-wires them so they
// can be exported to Prometheus
type Collector struct {
	metricsMapSpec *ebpf.MapSpec
	metricsMap     *ebpf.Map
	keyFields      []columns.DynamicField
	valueFields    []columns.DynamicField
}

func NewCollector(spec *ebpf.CollectionSpec) (*Collector, error) {
	metricsMapSpec, ok := spec.Maps[MetricsMapName]
	if !ok {
		return nil, ErrUnsupported
	}
	c := &Collector{
		metricsMapSpec: metricsMapSpec,
	}

	key, ok := metricsMapSpec.Key.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("BPF map %q does not have BTF info for key", metricsMapSpec.Name)
	}
	value, ok := metricsMapSpec.Value.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("BPF map %q does not have BTF info for value", metricsMapSpec.Name)
	}

	keyFields, err := btfutils.GetFieldsFromBTF(key)
	if err != nil {
		return nil, fmt.Errorf("extracting fields from key: %w", err)
	}
	c.keyFields = keyFields

	valueFields, err := btfutils.GetFieldsFromBTF(value)
	if err != nil {
		return nil, fmt.Errorf("extracting fields from value: %w", err)
	}
	c.valueFields = valueFields
	return c, nil
}

func (c *Collector) Columns() (*columns.Columns[CollectorData], error) {
	cols := columns.MustCreateColumns[CollectorData]()
	err := cols.AddFields(c.keyFields, func(c *CollectorData) unsafe.Pointer {
		return unsafe.Pointer(&c.key[0])
	})
	if err != nil {
		return nil, fmt.Errorf("adding key fields")
	}
	err = cols.AddFields(c.valueFields, func(c *CollectorData) unsafe.Pointer {
		return unsafe.Pointer(&c.values[0])
	})
	if err != nil {
		return nil, fmt.Errorf("adding value fields")
	}
	return cols, nil
}

// TODO: gadgets.GadgetInstantiate + SetMetricsProvider
