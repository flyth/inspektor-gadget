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

// StructBuilder accumulates encoded field data.
// Used within encode callbacks to set field values efficiently.
// All Put methods write directly to the internal buffer without type switches.
type StructBuilder struct {
	buf []byte
}

// Reset clears the builder for reuse.
func (b *StructBuilder) Reset() {
	b.buf = b.buf[:0]
}

// Bytes returns the encoded data. The returned slice is only valid until the next Reset.
func (b *StructBuilder) Bytes() []byte {
	return b.buf
}

// PutBool encodes a bool field.
func (b *StructBuilder) PutBool(fieldNum int, v bool) {
	if v {
		b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.VarintType)
		b.buf = protowire.AppendVarint(b.buf, 1)
	}
	// Skip false values (proto3 default)
}

// PutInt32 encodes an int32 field using fixed32.
func (b *StructBuilder) PutInt32(fieldNum int, v int32) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed32Type)
	b.buf = protowire.AppendFixed32(b.buf, uint32(v))
}

// PutInt64 encodes an int64 field using fixed64.
func (b *StructBuilder) PutInt64(fieldNum int, v int64) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed64Type)
	b.buf = protowire.AppendFixed64(b.buf, uint64(v))
}

// PutUint32 encodes a uint32 field using fixed32.
func (b *StructBuilder) PutUint32(fieldNum int, v uint32) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed32Type)
	b.buf = protowire.AppendFixed32(b.buf, v)
}

// PutUint64 encodes a uint64 field using fixed64.
func (b *StructBuilder) PutUint64(fieldNum int, v uint64) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed64Type)
	b.buf = protowire.AppendFixed64(b.buf, v)
}

// PutFloat32 encodes a float32 field.
func (b *StructBuilder) PutFloat32(fieldNum int, v float32) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed32Type)
	b.buf = protowire.AppendFixed32(b.buf, math.Float32bits(v))
}

// PutFloat64 encodes a float64 field.
func (b *StructBuilder) PutFloat64(fieldNum int, v float64) {
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.Fixed64Type)
	b.buf = protowire.AppendFixed64(b.buf, math.Float64bits(v))
}

// PutString encodes a string field.
func (b *StructBuilder) PutString(fieldNum int, v string) {
	if len(v) > 0 { // Skip empty strings (proto3 default)
		b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.BytesType)
		b.buf = protowire.AppendString(b.buf, v)
	}
}

// PutBytes encodes a bytes field.
func (b *StructBuilder) PutBytes(fieldNum int, v []byte) {
	if len(v) > 0 { // Skip empty bytes (proto3 default)
		b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.BytesType)
		b.buf = protowire.AppendBytes(b.buf, v)
	}
}

// PutUint32Array encodes a packed uint32 array field.
func (b *StructBuilder) PutUint32Array(fieldNum int, values []uint32) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Uint32Codec)
}

// PutUint64Array encodes a packed uint64 array field.
func (b *StructBuilder) PutUint64Array(fieldNum int, values []uint64) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Uint64Codec)
}

// PutInt32Array encodes a packed int32 array field.
func (b *StructBuilder) PutInt32Array(fieldNum int, values []int32) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Int32Codec)
}

// PutInt64Array encodes a packed int64 array field.
func (b *StructBuilder) PutInt64Array(fieldNum int, values []int64) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Int64Codec)
}

// PutFloat32Array encodes a packed float32 array field.
func (b *StructBuilder) PutFloat32Array(fieldNum int, values []float32) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Float32Codec)
}

// PutFloat64Array encodes a packed float64 array field.
func (b *StructBuilder) PutFloat64Array(fieldNum int, values []float64) {
	if len(values) == 0 {
		return
	}
	b.buf = EncodePackedArray(b.buf, fieldNum, values, Float64Codec)
}

// PutStringArray encodes a repeated string field.
func (b *StructBuilder) PutStringArray(fieldNum int, values []string) {
	for _, s := range values {
		b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.BytesType)
		b.buf = protowire.AppendString(b.buf, s)
	}
}

// PutBytesArray encodes a repeated bytes field.
func (b *StructBuilder) PutBytesArray(fieldNum int, values [][]byte) {
	for _, v := range values {
		b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.BytesType)
		b.buf = protowire.AppendBytes(b.buf, v)
	}
}

// PutNestedMessage encodes nested message bytes as a field.
func (b *StructBuilder) PutNestedMessage(fieldNum int, data []byte) {
	if len(data) == 0 {
		return
	}
	b.buf = protowire.AppendTag(b.buf, protowire.Number(fieldNum), protowire.BytesType)
	b.buf = protowire.AppendBytes(b.buf, data)
}

// StructFieldAccessor provides typed access to a specific struct field.
// Each field gets its own accessor that knows its field number,
// avoiding runtime lookups and type switches.
type StructFieldAccessor struct {
	fieldNum int
	kind     api.Kind
	elemKind api.Kind        // For arrays
	nested   *StructAccessor // For nested structs
}

// FieldNum returns the protobuf field number.
func (f *StructFieldAccessor) FieldNum() int {
	return f.fieldNum
}

// Kind returns the field's api.Kind.
func (f *StructFieldAccessor) Kind() api.Kind {
	return f.kind
}

// PutBool encodes a bool value for this field.
func (f *StructFieldAccessor) PutBool(b *StructBuilder, v bool) {
	b.PutBool(f.fieldNum, v)
}

// PutInt32 encodes an int32 value for this field.
func (f *StructFieldAccessor) PutInt32(b *StructBuilder, v int32) {
	b.PutInt32(f.fieldNum, v)
}

// PutInt64 encodes an int64 value for this field.
func (f *StructFieldAccessor) PutInt64(b *StructBuilder, v int64) {
	b.PutInt64(f.fieldNum, v)
}

// PutUint32 encodes a uint32 value for this field.
func (f *StructFieldAccessor) PutUint32(b *StructBuilder, v uint32) {
	b.PutUint32(f.fieldNum, v)
}

// PutUint64 encodes a uint64 value for this field.
func (f *StructFieldAccessor) PutUint64(b *StructBuilder, v uint64) {
	b.PutUint64(f.fieldNum, v)
}

// PutFloat32 encodes a float32 value for this field.
func (f *StructFieldAccessor) PutFloat32(b *StructBuilder, v float32) {
	b.PutFloat32(f.fieldNum, v)
}

// PutFloat64 encodes a float64 value for this field.
func (f *StructFieldAccessor) PutFloat64(b *StructBuilder, v float64) {
	b.PutFloat64(f.fieldNum, v)
}

// PutString encodes a string value for this field.
func (f *StructFieldAccessor) PutString(b *StructBuilder, v string) {
	b.PutString(f.fieldNum, v)
}

// PutBytes encodes a bytes value for this field.
func (f *StructFieldAccessor) PutBytes(b *StructBuilder, v []byte) {
	b.PutBytes(f.fieldNum, v)
}

// PutUint32Array encodes a uint32 array for this field.
func (f *StructFieldAccessor) PutUint32Array(b *StructBuilder, values []uint32) {
	b.PutUint32Array(f.fieldNum, values)
}

// PutUint64Array encodes a uint64 array for this field.
func (f *StructFieldAccessor) PutUint64Array(b *StructBuilder, values []uint64) {
	b.PutUint64Array(f.fieldNum, values)
}

// PutInt32Array encodes an int32 array for this field.
func (f *StructFieldAccessor) PutInt32Array(b *StructBuilder, values []int32) {
	b.PutInt32Array(f.fieldNum, values)
}

// PutInt64Array encodes an int64 array for this field.
func (f *StructFieldAccessor) PutInt64Array(b *StructBuilder, values []int64) {
	b.PutInt64Array(f.fieldNum, values)
}

// PutFloat32Array encodes a float32 array for this field.
func (f *StructFieldAccessor) PutFloat32Array(b *StructBuilder, values []float32) {
	b.PutFloat32Array(f.fieldNum, values)
}

// PutFloat64Array encodes a float64 array for this field.
func (f *StructFieldAccessor) PutFloat64Array(b *StructBuilder, values []float64) {
	b.PutFloat64Array(f.fieldNum, values)
}

// PutStringArray encodes a string array for this field.
func (f *StructFieldAccessor) PutStringArray(b *StructBuilder, values []string) {
	b.PutStringArray(f.fieldNum, values)
}

// PutBytesArray encodes a bytes array for this field.
func (f *StructFieldAccessor) PutBytesArray(b *StructBuilder, values [][]byte) {
	b.PutBytesArray(f.fieldNum, values)
}

// PutNested encodes a nested struct using a callback.
func (f *StructFieldAccessor) PutNested(b *StructBuilder, fn func(nb *StructBuilder)) {
	if f.nested == nil {
		return
	}
	nestedBytes := f.nested.EncodeCallback(fn)
	b.PutNestedMessage(f.fieldNum, nestedBytes)
}

// PutNestedArray encodes an array of nested structs using a callback per element.
func (f *StructFieldAccessor) PutNestedArray(b *StructBuilder, count int, fn func(idx int, nb *StructBuilder)) {
	if f.nested == nil || count == 0 {
		return
	}
	for i := 0; i < count; i++ {
		nestedBytes := f.nested.EncodeCallback(func(nb *StructBuilder) {
			fn(i, nb)
		})
		b.PutNestedMessage(f.fieldNum, nestedBytes)
	}
}

// StructAccessor provides efficient struct encoding with typed field access.
// It pre-builds field accessors during initialization for zero-overhead encoding.
type StructAccessor struct {
	def      *StructDef
	fields   []*StructFieldAccessor
	fieldMap map[string]*StructFieldAccessor
	builder  StructBuilder // Reusable builder
	decoder  *StructDecoder
}

// NewStructAccessor creates a new StructAccessor for the given definition.
// Field accessors are pre-built during initialization.
func NewStructAccessor(def *StructDef) (*StructAccessor, error) {
	a := &StructAccessor{
		def:      def,
		fields:   make([]*StructFieldAccessor, len(def.Fields)),
		fieldMap: make(map[string]*StructFieldAccessor, len(def.Fields)),
		builder:  StructBuilder{buf: make([]byte, 0, DefaultEncoderCapacity)},
	}

	// Pre-build field accessors
	for i, fieldDef := range def.Fields {
		fa := &StructFieldAccessor{
			fieldNum: fieldDef.FieldNum,
			kind:     fieldDef.Kind,
			elemKind: fieldDef.ElemKind,
		}

		// For nested structs, create nested accessor
		if fieldDef.Kind == api.Kind_Kind_Struct || fieldDef.Kind == api.Kind_Kind_StructArray {
			if fieldDef.NestedDef != nil {
				nested, err := NewStructAccessor(fieldDef.NestedDef)
				if err != nil {
					return nil, fmt.Errorf("creating nested accessor for %s: %w", fieldDef.Name, err)
				}
				fa.nested = nested
			}
		}

		a.fields[i] = fa
		a.fieldMap[fieldDef.Name] = fa
	}

	// Create decoder (lazy initialization would also work)
	decoder, err := NewStructDecoder(def)
	if err != nil {
		return nil, fmt.Errorf("creating decoder: %w", err)
	}
	a.decoder = decoder

	return a, nil
}

// Field returns the field accessor at the given index.
// This is the fastest way to access fields.
func (a *StructAccessor) Field(idx int) *StructFieldAccessor {
	if idx < 0 || idx >= len(a.fields) {
		return nil
	}
	return a.fields[idx]
}

// FieldByName returns the field accessor for the given field name.
// Slower than Field() due to map lookup.
func (a *StructAccessor) FieldByName(name string) *StructFieldAccessor {
	return a.fieldMap[name]
}

// NumFields returns the number of fields in the struct.
func (a *StructAccessor) NumFields() int {
	return len(a.fields)
}

// EncodeCallback encodes a struct using a callback and returns the bytes.
// The callback sets field values using the StructBuilder.
// Returns a copy of the encoded data (safe to store).
func (a *StructAccessor) EncodeCallback(fn func(b *StructBuilder)) []byte {
	a.builder.Reset()
	fn(&a.builder)
	// Return a copy
	result := make([]byte, len(a.builder.buf))
	copy(result, a.builder.buf)
	return result
}

// EncodeCallbackTo encodes a struct using a callback into an existing buffer.
// Returns the slice with encoded data appended.
// More efficient when you already have a buffer to append to.
func (a *StructAccessor) EncodeCallbackTo(dst []byte, fn func(b *StructBuilder)) []byte {
	a.builder.Reset()
	fn(&a.builder)
	return append(dst, a.builder.buf...)
}

// EncodeStructArrayCallback encodes an array of structs using a callback per element.
// The fieldNum is the protobuf field number for the array.
func (a *StructAccessor) EncodeStructArrayCallback(fieldNum int, count int, fn func(idx int, b *StructBuilder)) []byte {
	if count == 0 {
		return nil
	}

	// Use a separate buffer for the final result
	result := make([]byte, 0, count*64) // Estimate

	for i := 0; i < count; i++ {
		a.builder.Reset()
		fn(i, &a.builder)

		// Append as nested message
		result = protowire.AppendTag(result, protowire.Number(fieldNum), protowire.BytesType)
		result = protowire.AppendBytes(result, a.builder.buf)
	}

	return result
}

// Decode decodes protobuf bytes to map[string]any.
// Uses the pre-built decoder.
func (a *StructAccessor) Decode(data []byte) (map[string]any, error) {
	return a.decoder.Decode(data)
}

// DecodeStructArray decodes an array of structs.
func (a *StructAccessor) DecodeStructArray(data []byte) ([]map[string]any, error) {
	return a.decoder.DecodeStructArray(data)
}

// Encoder returns the legacy StructEncoder for backwards compatibility.
func (a *StructAccessor) Encoder() *StructEncoder {
	return NewStructEncoder(a.def, DefaultEncoderCapacity)
}

// Decoder returns the StructDecoder.
func (a *StructAccessor) Decoder() *StructDecoder {
	return a.decoder
}
