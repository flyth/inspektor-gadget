// Copyright 2024 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

type mapPullHook int

const (
	mapPullHookInterval mapPullHook = iota
	mapPullHookEnd
)

type mapPullType int

const (
	mapPullTypeEvent mapPullType = iota
	mapPullTypeArray
)

type mapAttrs struct {
	pullHook    mapPullHook
	pullType    mapPullType
	annotations map[string]string
}

type MapSource struct {
	MapName       string
	KeyStructName string
	ValStructName string
	keySize       uint32
	valSize       uint32
	ds            datasource.DataSource
	keyAccessor   datasource.FieldAccessor
	valAccessor   datasource.FieldAccessor
	metricsMap    *ebpf.Map
}

func (i *ebpfInstance) populateMapSource(attrs mapAttrs) func(t btf.Type, varName string) error {
	return func(t btf.Type, varName string) error {
		i.logger.Debugf("populating profiler %q", varName)

		parts := strings.Split(varName, typeSplitter)
		if len(parts) != 4 {
			return fmt.Errorf("invalid tracer info: %q", varName)
		}

		name := parts[0]
		mapName := parts[1]
		keyStructName := parts[2]
		valStructName := parts[3]

		i.logger.Debugf("> name           : %q", name)
		i.logger.Debugf("> map name       : %q", mapName)
		i.logger.Debugf("> key struct name: %q", keyStructName)
		i.logger.Debugf("> val struct name: %q", valStructName)

		// metricsMap, ok := i.collectionSpec.Maps[mapName]
		// if !ok {
		// 	return fmt.Errorf("map %q not found in eBPF object", mapName)
		// }

		var keyBtfStruct *btf.Struct
		if err := i.collectionSpec.Types.TypeByName(keyStructName, &keyBtfStruct); err != nil {
			return fmt.Errorf("finding struct %q in eBPF object: %w", keyStructName, err)
		}

		var valBtfStruct *btf.Struct
		if err := i.collectionSpec.Types.TypeByName(valStructName, &valBtfStruct); err != nil {
			return fmt.Errorf("finding struct %q in eBPF object: %w", valStructName, err)
		}

		i.metrics[name] = &MapSource{
			MapName:       mapName,
			KeyStructName: keyBtfStruct.Name,
			keySize:       keyBtfStruct.Size,
			ValStructName: valBtfStruct.Name,
			valSize:       valBtfStruct.Size,
		}

		err := i.populateStructDirect(keyBtfStruct)
		if err != nil {
			return fmt.Errorf("populating struct %q for metrics %q: %w", keyBtfStruct.Name, name, err)
		}

		err = i.populateStructDirect(valBtfStruct)
		if err != nil {
			return fmt.Errorf("populating struct %q for metrics %q: %w", valBtfStruct.Name, name, err)
		}

		return nil
	}
}

func (i *ebpfInstance) runMetrics() error {
	for _, m := range i.metrics {
		m := m
		go func() {
			ticker := time.NewTicker(time.Second * 1)
			for {
				select {
				case <-i.gadgetCtx.Context().Done():
				case <-ticker.C:
					m.metricsMap = i.collection.Maps[m.MapName]
					key := make([]byte, m.metricsMap.KeySize())
					value := make([]byte, m.metricsMap.ValueSize())

					it := m.metricsMap.Iterate()
					for it.Next(&key, &value) {
						data := m.ds.NewData()
						m.keyAccessor.Set(data, key)
						m.valAccessor.Set(data, value)
						m.ds.EmitAndRelease(data)
					}

					err := it.Err()
					if err != nil {
						i.logger.Warnf("iterating over metrica map: %v", err)
						// return fmt.Errorf("iterating over profiler map: %w", err)
					}
				}
			}
		}()
	}
	return nil
}

// type Metrics struct {
// 	MapName       string
// 	KeyStructName string
// 	ValStructName string
// 	keySize       uint32
// 	valSize       uint32
// 	ds            datasource.DataSource
// 	keyAccessor   datasource.FieldAccessor
// 	valAccessor   datasource.FieldAccessor
// 	metricsMap    *ebpf.Map
// }
//
// func (i *ebpfInstance) populateMetrics(t btf.Type, varName string) error {
// 	i.logger.Debugf("populating profiler %q", varName)
//
// 	parts := strings.Split(varName, typeSplitter)
// 	if len(parts) != 4 {
// 		return fmt.Errorf("invalid tracer info: %q", varName)
// 	}
//
// 	name := parts[0]
// 	mapName := parts[1]
// 	keyStructName := parts[2]
// 	valStructName := parts[3]
//
// 	i.logger.Debugf("> name           : %q", name)
// 	i.logger.Debugf("> map name       : %q", mapName)
// 	i.logger.Debugf("> key struct name: %q", keyStructName)
// 	i.logger.Debugf("> val struct name: %q", valStructName)
//
// 	// metricsMap, ok := i.collectionSpec.Maps[mapName]
// 	// if !ok {
// 	// 	return fmt.Errorf("map %q not found in eBPF object", mapName)
// 	// }
//
// 	var keyBtfStruct *btf.Struct
// 	if err := i.collectionSpec.Types.TypeByName(keyStructName, &keyBtfStruct); err != nil {
// 		return fmt.Errorf("finding struct %q in eBPF object: %w", keyStructName, err)
// 	}
//
// 	var valBtfStruct *btf.Struct
// 	if err := i.collectionSpec.Types.TypeByName(valStructName, &valBtfStruct); err != nil {
// 		return fmt.Errorf("finding struct %q in eBPF object: %w", valStructName, err)
// 	}
//
// 	i.metrics[name] = &Metrics{
// 		MapName:       mapName,
// 		KeyStructName: keyBtfStruct.Name,
// 		keySize:       keyBtfStruct.Size,
// 		ValStructName: valBtfStruct.Name,
// 		valSize:       valBtfStruct.Size,
// 	}
//
// 	err := i.populateStructDirect(keyBtfStruct)
// 	if err != nil {
// 		return fmt.Errorf("populating struct %q for metrics %q: %w", keyBtfStruct.Name, name, err)
// 	}
//
// 	err = i.populateStructDirect(valBtfStruct)
// 	if err != nil {
// 		return fmt.Errorf("populating struct %q for metrics %q: %w", valBtfStruct.Name, name, err)
// 	}
//
// 	return nil
// }
//
// func (i *ebpfInstance) runMetrics() error {
// 	for _, m := range i.metrics {
// 		m := m
// 		go func() {
// 			ticker := time.NewTicker(time.Second * 1)
// 			for {
// 				select {
// 				case <-i.gadgetCtx.Context().Done():
// 				case <-ticker.C:
// 					m.metricsMap = i.collection.Maps[m.MapName]
// 					key := make([]byte, m.metricsMap.KeySize())
// 					value := make([]byte, m.metricsMap.ValueSize())
//
// 					it := m.metricsMap.Iterate()
// 					for it.Next(&key, &value) {
// 						data := m.ds.NewData()
// 						m.keyAccessor.Set(data, key)
// 						m.valAccessor.Set(data, value)
// 						m.ds.EmitAndRelease(data)
// 					}
//
// 					err := it.Err()
// 					if err != nil {
// 						i.logger.Warnf("iterating over metrica map: %v", err)
// 						// return fmt.Errorf("iterating over profiler map: %w", err)
// 					}
// 				}
// 			}
// 		}()
// 	}
// 	return nil
// }
