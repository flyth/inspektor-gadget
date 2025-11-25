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
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// Buffer capacity constants for encoder allocation.
const (
	// DefaultEncoderCapacity is a reasonable default for small arrays/structs.
	DefaultEncoderCapacity = 256

	// LargeEncoderCapacity is for larger structures with many fields.
	LargeEncoderCapacity = 1024

	// ProtoHeaderOverhead accounts for tag and length varint in protobuf encoding.
	// Used when calculating buffer size: elemCount * elemSize + ProtoHeaderOverhead.
	ProtoHeaderOverhead = 16
)

// Kind type aliases for cleaner code
type Kind = api.Kind

const (
	Kind_Bool             = api.Kind_Bool
	Kind_Int8             = api.Kind_Int8
	Kind_Int16            = api.Kind_Int16
	Kind_Int32            = api.Kind_Int32
	Kind_Int64            = api.Kind_Int64
	Kind_Uint8            = api.Kind_Uint8
	Kind_Uint16           = api.Kind_Uint16
	Kind_Uint32           = api.Kind_Uint32
	Kind_Uint64           = api.Kind_Uint64
	Kind_Float32          = api.Kind_Float32
	Kind_Float64          = api.Kind_Float64
	Kind_String           = api.Kind_String
	Kind_CString          = api.Kind_CString
	Kind_Bytes            = api.Kind_Bytes
	Kind_Kind_Struct      = api.Kind_Kind_Struct
	Kind_Kind_StructArray = api.Kind_Kind_StructArray
	KindFlagArray         = api.KindFlagArray
)

// IsArrayKind returns true if the kind represents an array type.
var IsArrayKind = api.IsArrayKind

// ArrayEncoder encodes typed arrays to protobuf wire format.
// It pre-allocates a buffer and provides methods for encoding various array types
// using packed repeated fields for efficiency.
//
// The encoder is designed for dynamic arrays created by operators, not for
// static eBPF arrays (which use zero-copy via unsafe.Slice).
type ArrayEncoder struct {
	buf []byte
}

// NewArrayEncoder creates a new ArrayEncoder with a pre-allocated buffer.
// The capacity parameter specifies the initial buffer size in bytes.
// A good starting capacity is 256-512 bytes for typical arrays.
func NewArrayEncoder(capacity int) *ArrayEncoder {
	return &ArrayEncoder{
		buf: make([]byte, 0, capacity),
	}
}

// Reset clears the internal buffer for reuse, keeping the allocated capacity.
// This allows the encoder to be reused without additional allocations.
func (e *ArrayEncoder) Reset() {
	e.buf = e.buf[:0]
}

// EncodeUint32Array encodes a []uint32 slice as a packed repeated field.
// Uses fixed32 encoding (4 bytes per element, little-endian).
func (e *ArrayEncoder) EncodeUint32Array(fieldNum int, values []uint32) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Uint32Codec)
	return e.buf
}

// EncodeUint64Array encodes a []uint64 slice as a packed repeated field.
// Uses fixed64 encoding (8 bytes per element, little-endian).
func (e *ArrayEncoder) EncodeUint64Array(fieldNum int, values []uint64) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Uint64Codec)
	return e.buf
}

// EncodeInt32Array encodes a []int32 slice as a packed repeated field.
// Uses fixed32 encoding for consistent 4-byte representation.
func (e *ArrayEncoder) EncodeInt32Array(fieldNum int, values []int32) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Int32Codec)
	return e.buf
}

// EncodeInt64Array encodes a []int64 slice as a packed repeated field.
// Uses fixed64 encoding for consistent 8-byte representation.
func (e *ArrayEncoder) EncodeInt64Array(fieldNum int, values []int64) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Int64Codec)
	return e.buf
}

// EncodeFloat32Array encodes a []float32 slice as a packed repeated field.
// Uses fixed32 encoding (IEEE 754 binary32 format).
func (e *ArrayEncoder) EncodeFloat32Array(fieldNum int, values []float32) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Float32Codec)
	return e.buf
}

// EncodeFloat64Array encodes a []float64 slice as a packed repeated field.
// Uses fixed64 encoding (IEEE 754 binary64 format).
func (e *ArrayEncoder) EncodeFloat64Array(fieldNum int, values []float64) []byte {
	if len(values) == 0 {
		return nil
	}
	e.buf = e.buf[:0]
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Float64Codec)
	return e.buf
}

// EncodeStringArray encodes a []string slice as a repeated field (non-packed).
// Each string is length-delimited, so they cannot be packed together.
//
// Wire format: [tag] [len1] [str1] [tag] [len2] [str2] ...
func (e *ArrayEncoder) EncodeStringArray(fieldNum int, values []string) []byte {
	if len(values) == 0 {
		return nil
	}

	e.buf = e.buf[:0]

	for _, s := range values {
		e.buf = protowire.AppendTag(e.buf, protowire.Number(fieldNum), protowire.BytesType)
		e.buf = protowire.AppendString(e.buf, s)
	}

	return e.buf
}

// EncodeBytesArray encodes a [][]byte slice as a repeated field (non-packed).
// Each byte slice is length-delimited.
//
// Wire format: [tag] [len1] [bytes1] [tag] [len2] [bytes2] ...
func (e *ArrayEncoder) EncodeBytesArray(fieldNum int, values [][]byte) []byte {
	if len(values) == 0 {
		return nil
	}

	e.buf = e.buf[:0]

	for _, b := range values {
		e.buf = protowire.AppendTag(e.buf, protowire.Number(fieldNum), protowire.BytesType)
		e.buf = protowire.AppendBytes(e.buf, b)
	}

	return e.buf
}

// StructEncoder encodes Go maps to protobuf wire format based on a StructDef.
// It supports scalar fields, array fields, and nested struct fields.
type StructEncoder struct {
	buf []byte
	def *StructDef
}

// NewStructEncoder creates a new StructEncoder for a specific struct definition.
// The capacity parameter specifies the initial buffer size in bytes.
func NewStructEncoder(def *StructDef, capacity int) *StructEncoder {
	return &StructEncoder{
		buf: make([]byte, 0, capacity),
		def: def,
	}
}

// Reset clears the internal buffer for reuse.
func (e *StructEncoder) Reset() {
	e.buf = e.buf[:0]
}

// Encode encodes a struct value (map[string]any) to protobuf bytes.
// Missing fields in the map are skipped (protobuf allows this).
func (e *StructEncoder) Encode(value map[string]any) ([]byte, error) {
	e.Reset()

	for _, field := range e.def.Fields {
		v, ok := value[field.Name]
		if !ok {
			continue // Skip missing fields
		}

		if err := e.encodeField(field, v); err != nil {
			return nil, fmt.Errorf("encoding field %s: %w", field.Name, err)
		}
	}

	// Return a copy so the internal buffer can be reused
	result := make([]byte, len(e.buf))
	copy(result, e.buf)
	return result, nil
}

// encodeField encodes a single field value to the buffer.
func (e *StructEncoder) encodeField(field StructFieldDef, value any) error {
	switch {
	case field.Kind == Kind_Kind_Struct:
		// Nested struct: recursively encode
		return e.encodeNestedStruct(field, value)

	case field.Kind == Kind_Kind_StructArray:
		// Array of structs
		return e.encodeStructArray(field, value)

	case IsArrayKind(field.Kind):
		// Array of scalars
		return e.encodeArrayField(field, value)

	default:
		// Scalar field
		return e.encodeScalarField(field, value)
	}
}

// encodeNestedStruct encodes a nested struct field.
func (e *StructEncoder) encodeNestedStruct(field StructFieldDef, value any) error {
	nested, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any for nested struct, got %T", value)
	}

	nestedEncoder := NewStructEncoder(field.NestedDef, 128)
	nestedBytes, err := nestedEncoder.Encode(nested)
	if err != nil {
		return err
	}

	e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.BytesType)
	e.buf = protowire.AppendBytes(e.buf, nestedBytes)
	return nil
}

// encodeStructArray encodes an array of structs.
func (e *StructEncoder) encodeStructArray(field StructFieldDef, value any) error {
	arr, ok := value.([]map[string]any)
	if !ok {
		// Try []any and convert
		anyArr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected []map[string]any for struct array, got %T", value)
		}
		arr = make([]map[string]any, len(anyArr))
		for i, v := range anyArr {
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("expected map[string]any at index %d, got %T", i, v)
			}
			arr[i] = m
		}
	}

	nestedEncoder := NewStructEncoder(field.NestedDef, 128)
	for _, item := range arr {
		nestedBytes, err := nestedEncoder.Encode(item)
		if err != nil {
			return fmt.Errorf("encoding struct array element: %w", err)
		}

		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.BytesType)
		e.buf = protowire.AppendBytes(e.buf, nestedBytes)
		nestedEncoder.Reset()
	}
	return nil
}

// encodeArrayField encodes an array of scalars.
func (e *StructEncoder) encodeArrayField(field StructFieldDef, value any) error {
	elemKind := field.ElemKind
	if elemKind == 0 {
		elemKind = field.Kind & ^KindFlagArray
	}

	switch elemKind {
	case Kind_Uint32:
		arr, ok := toUint32Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []uint32", value)
		}
		e.encodePackedUint32(field.FieldNum, arr)

	case Kind_Uint64:
		arr, ok := toUint64Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []uint64", value)
		}
		e.encodePackedUint64(field.FieldNum, arr)

	case Kind_Int32:
		arr, ok := toInt32Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []int32", value)
		}
		e.encodePackedInt32(field.FieldNum, arr)

	case Kind_Int64:
		arr, ok := toInt64Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []int64", value)
		}
		e.encodePackedInt64(field.FieldNum, arr)

	case Kind_Float32:
		arr, ok := toFloat32Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []float32", value)
		}
		e.encodePackedFloat32(field.FieldNum, arr)

	case Kind_Float64:
		arr, ok := toFloat64Slice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []float64", value)
		}
		e.encodePackedFloat64(field.FieldNum, arr)

	case Kind_String, Kind_CString:
		arr, ok := toStringSlice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to []string", value)
		}
		e.encodeStringArray(field.FieldNum, arr)

	case Kind_Bytes:
		arr, ok := toBytesSlice(value)
		if !ok {
			return fmt.Errorf("cannot convert %T to [][]byte", value)
		}
		e.encodeBytesArray(field.FieldNum, arr)

	default:
		return fmt.Errorf("unsupported array element kind: %v", elemKind)
	}

	return nil
}

// encodeScalarField encodes a scalar field.
func (e *StructEncoder) encodeScalarField(field StructFieldDef, value any) error {
	switch field.Kind {
	case Kind_Bool:
		v, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}
		if v {
			e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.VarintType)
			e.buf = protowire.AppendVarint(e.buf, 1)
		}
		// Skip false values (proto3 default)

	case Kind_Int8, Kind_Int16, Kind_Int32:
		v, ok := toInt32(value)
		if !ok {
			return fmt.Errorf("expected int32-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed32Type)
		e.buf = protowire.AppendFixed32(e.buf, uint32(v))

	case Kind_Int64:
		v, ok := toInt64(value)
		if !ok {
			return fmt.Errorf("expected int64-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed64Type)
		e.buf = protowire.AppendFixed64(e.buf, uint64(v))

	case Kind_Uint8, Kind_Uint16, Kind_Uint32:
		v, ok := toUint32(value)
		if !ok {
			return fmt.Errorf("expected uint32-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed32Type)
		e.buf = protowire.AppendFixed32(e.buf, v)

	case Kind_Uint64:
		v, ok := toUint64(value)
		if !ok {
			return fmt.Errorf("expected uint64-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed64Type)
		e.buf = protowire.AppendFixed64(e.buf, v)

	case Kind_Float32:
		v, ok := toFloat32(value)
		if !ok {
			return fmt.Errorf("expected float32-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed32Type)
		e.buf = protowire.AppendFixed32(e.buf, math.Float32bits(v))

	case Kind_Float64:
		v, ok := toFloat64(value)
		if !ok {
			return fmt.Errorf("expected float64-compatible, got %T", value)
		}
		e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.Fixed64Type)
		e.buf = protowire.AppendFixed64(e.buf, math.Float64bits(v))

	case Kind_String, Kind_CString:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		if len(v) > 0 { // Skip empty strings (proto3 default)
			e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.BytesType)
			e.buf = protowire.AppendString(e.buf, v)
		}

	case Kind_Bytes:
		v, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("expected []byte, got %T", value)
		}
		if len(v) > 0 { // Skip empty bytes (proto3 default)
			e.buf = protowire.AppendTag(e.buf, protowire.Number(field.FieldNum), protowire.BytesType)
			e.buf = protowire.AppendBytes(e.buf, v)
		}

	default:
		return fmt.Errorf("unsupported scalar kind: %v", field.Kind)
	}

	return nil
}

// Packed encoding helpers for struct encoder

func (e *StructEncoder) encodePackedUint32(fieldNum int, values []uint32) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Uint32Codec)
}

func (e *StructEncoder) encodePackedUint64(fieldNum int, values []uint64) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Uint64Codec)
}

func (e *StructEncoder) encodePackedInt32(fieldNum int, values []int32) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Int32Codec)
}

func (e *StructEncoder) encodePackedInt64(fieldNum int, values []int64) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Int64Codec)
}

func (e *StructEncoder) encodePackedFloat32(fieldNum int, values []float32) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Float32Codec)
}

func (e *StructEncoder) encodePackedFloat64(fieldNum int, values []float64) {
	if len(values) == 0 {
		return
	}
	e.buf = EncodePackedArray(e.buf, fieldNum, values, Float64Codec)
}

func (e *StructEncoder) encodeStringArray(fieldNum int, values []string) {
	for _, s := range values {
		e.buf = protowire.AppendTag(e.buf, protowire.Number(fieldNum), protowire.BytesType)
		e.buf = protowire.AppendString(e.buf, s)
	}
}

func (e *StructEncoder) encodeBytesArray(fieldNum int, values [][]byte) {
	for _, b := range values {
		e.buf = protowire.AppendTag(e.buf, protowire.Number(fieldNum), protowire.BytesType)
		e.buf = protowire.AppendBytes(e.buf, b)
	}
}

// EncodeStructArray encodes a slice of structs as repeated embedded messages.
// This is a convenience function for encoding an array of structs without wrapping.
func (e *StructEncoder) EncodeStructArray(fieldNum int, values []map[string]any) ([]byte, error) {
	e.Reset()

	for _, item := range values {
		nestedEncoder := NewStructEncoder(e.def, 128)
		nestedBytes, err := nestedEncoder.Encode(item)
		if err != nil {
			return nil, fmt.Errorf("encoding struct array element: %w", err)
		}

		e.buf = protowire.AppendTag(e.buf, protowire.Number(fieldNum), protowire.BytesType)
		e.buf = protowire.AppendBytes(e.buf, nestedBytes)
	}

	result := make([]byte, len(e.buf))
	copy(result, e.buf)
	return result, nil
}

// Type conversion helpers

func toUint32(v any) (uint32, bool) {
	switch x := v.(type) {
	case uint32:
		return x, true
	case uint:
		return uint32(x), true
	case uint8:
		return uint32(x), true
	case uint16:
		return uint32(x), true
	case uint64:
		return uint32(x), true
	case int:
		return uint32(x), true
	case int8:
		return uint32(x), true
	case int16:
		return uint32(x), true
	case int32:
		return uint32(x), true
	case int64:
		return uint32(x), true
	default:
		return 0, false
	}
}

func toUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case uint:
		return uint64(x), true
	case uint8:
		return uint64(x), true
	case uint16:
		return uint64(x), true
	case uint32:
		return uint64(x), true
	case int:
		return uint64(x), true
	case int8:
		return uint64(x), true
	case int16:
		return uint64(x), true
	case int32:
		return uint64(x), true
	case int64:
		return uint64(x), true
	default:
		return 0, false
	}
}

func toInt32(v any) (int32, bool) {
	switch x := v.(type) {
	case int32:
		return x, true
	case int:
		return int32(x), true
	case int8:
		return int32(x), true
	case int16:
		return int32(x), true
	case int64:
		return int32(x), true
	case uint:
		return int32(x), true
	case uint8:
		return int32(x), true
	case uint16:
		return int32(x), true
	case uint32:
		return int32(x), true
	case uint64:
		return int32(x), true
	default:
		return 0, false
	}
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case uint:
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	default:
		return 0, false
	}
}

func toFloat32(v any) (float32, bool) {
	switch x := v.(type) {
	case float32:
		return x, true
	case float64:
		return float32(x), true
	default:
		return 0, false
	}
}

func toFloat64(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	default:
		return 0, false
	}
}

func toUint32Slice(v any) ([]uint32, bool) {
	switch x := v.(type) {
	case []uint32:
		return x, true
	case []any:
		result := make([]uint32, len(x))
		for i, item := range x {
			val, ok := toUint32(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toUint64Slice(v any) ([]uint64, bool) {
	switch x := v.(type) {
	case []uint64:
		return x, true
	case []any:
		result := make([]uint64, len(x))
		for i, item := range x {
			val, ok := toUint64(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toInt32Slice(v any) ([]int32, bool) {
	switch x := v.(type) {
	case []int32:
		return x, true
	case []any:
		result := make([]int32, len(x))
		for i, item := range x {
			val, ok := toInt32(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toInt64Slice(v any) ([]int64, bool) {
	switch x := v.(type) {
	case []int64:
		return x, true
	case []any:
		result := make([]int64, len(x))
		for i, item := range x {
			val, ok := toInt64(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toFloat32Slice(v any) ([]float32, bool) {
	switch x := v.(type) {
	case []float32:
		return x, true
	case []any:
		result := make([]float32, len(x))
		for i, item := range x {
			val, ok := toFloat32(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toFloat64Slice(v any) ([]float64, bool) {
	switch x := v.(type) {
	case []float64:
		return x, true
	case []any:
		result := make([]float64, len(x))
		for i, item := range x {
			val, ok := toFloat64(item)
			if !ok {
				return nil, false
			}
			result[i] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func toStringSlice(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		result := make([]string, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			result[i] = s
		}
		return result, true
	default:
		return nil, false
	}
}

func toBytesSlice(v any) ([][]byte, bool) {
	switch x := v.(type) {
	case [][]byte:
		return x, true
	case []any:
		result := make([][]byte, len(x))
		for i, item := range x {
			b, ok := item.([]byte)
			if !ok {
				return nil, false
			}
			result[i] = b
		}
		return result, true
	default:
		return nil, false
	}
}
