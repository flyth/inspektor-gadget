// Copyright 2025 The Inspektor Gadget authors
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

package proto

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// kindConverter provides type-specific conversion operations for a Kind.
// This replaces large switch statements with map-based dispatch.
type kindConverter struct {
	// listToSlice extracts elements from a protoreflect.List into a typed slice.
	listToSlice func(list protoreflect.List) any

	// emptySlice returns an empty slice of the appropriate type.
	emptySlice func() any

	// scalarToGo converts a single protoreflect.Value to a Go value.
	scalarToGo func(v protoreflect.Value) any
}

// extractSlice is a generic helper for listToSlice implementations.
func extractSlice[T any](list protoreflect.List, convert func(protoreflect.Value) T) []T {
	n := list.Len()
	result := make([]T, n)
	for i := 0; i < n; i++ {
		result[i] = convert(list.Get(i))
	}
	return result
}

// kindConverters maps Kind to its type-specific converter.
// Initialized at package load time for fast lookup.
var kindConverters = map[api.Kind]kindConverter{
	api.Kind_Bool: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) bool { return v.Bool() })
		},
		emptySlice: func() any { return []bool{} },
		scalarToGo: func(v protoreflect.Value) any { return v.Bool() },
	},
	api.Kind_Int8: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) int8 { return int8(v.Int()) })
		},
		emptySlice: func() any { return []int8{} },
		scalarToGo: func(v protoreflect.Value) any { return int8(v.Int()) },
	},
	api.Kind_Int16: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) int16 { return int16(v.Int()) })
		},
		emptySlice: func() any { return []int16{} },
		scalarToGo: func(v protoreflect.Value) any { return int16(v.Int()) },
	},
	api.Kind_Int32: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) int32 { return int32(v.Int()) })
		},
		emptySlice: func() any { return []int32{} },
		scalarToGo: func(v protoreflect.Value) any { return int32(v.Int()) },
	},
	api.Kind_Int64: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) int64 { return v.Int() })
		},
		emptySlice: func() any { return []int64{} },
		scalarToGo: func(v protoreflect.Value) any { return v.Int() },
	},
	api.Kind_Uint8: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) uint8 { return uint8(v.Uint()) })
		},
		emptySlice: func() any { return []uint8{} },
		scalarToGo: func(v protoreflect.Value) any { return uint8(v.Uint()) },
	},
	api.Kind_Uint16: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) uint16 { return uint16(v.Uint()) })
		},
		emptySlice: func() any { return []uint16{} },
		scalarToGo: func(v protoreflect.Value) any { return uint16(v.Uint()) },
	},
	api.Kind_Uint32: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) uint32 { return uint32(v.Uint()) })
		},
		emptySlice: func() any { return []uint32{} },
		scalarToGo: func(v protoreflect.Value) any { return uint32(v.Uint()) },
	},
	api.Kind_Uint64: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) uint64 { return v.Uint() })
		},
		emptySlice: func() any { return []uint64{} },
		scalarToGo: func(v protoreflect.Value) any { return v.Uint() },
	},
	api.Kind_Float32: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) float32 { return float32(v.Float()) })
		},
		emptySlice: func() any { return []float32{} },
		scalarToGo: func(v protoreflect.Value) any { return float32(v.Float()) },
	},
	api.Kind_Float64: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) float64 { return v.Float() })
		},
		emptySlice: func() any { return []float64{} },
		scalarToGo: func(v protoreflect.Value) any { return v.Float() },
	},
	api.Kind_String: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) string { return v.String() })
		},
		emptySlice: func() any { return []string{} },
		scalarToGo: func(v protoreflect.Value) any { return v.String() },
	},
	api.Kind_CString: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) string { return v.String() })
		},
		emptySlice: func() any { return []string{} },
		scalarToGo: func(v protoreflect.Value) any { return v.String() },
	},
	api.Kind_Bytes: {
		listToSlice: func(l protoreflect.List) any {
			return extractSlice(l, func(v protoreflect.Value) []byte {
				b := v.Bytes()
				return append([]byte(nil), b...) // Make a copy
			})
		},
		emptySlice: func() any { return [][]byte{} },
		scalarToGo: func(v protoreflect.Value) any {
			b := v.Bytes()
			return append([]byte(nil), b...)
		},
	},
}

// getKindConverter returns the converter for a Kind, or nil if not found.
func getKindConverter(kind api.Kind) *kindConverter {
	if conv, ok := kindConverters[kind]; ok {
		return &conv
	}
	return nil
}

// convertAnySlice converts a []any to []T using a converter function.
// This is a generic helper for encoder type conversion.
func convertAnySlice[T any](arr []any, converter func(any) (T, bool)) ([]T, bool) {
	result := make([]T, len(arr))
	for i, item := range arr {
		val, ok := converter(item)
		if !ok {
			return nil, false
		}
		result[i] = val
	}
	return result, true
}
