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

package datasource

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/proto"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type InvalidFieldLengthErr struct {
	Expected int
	Actual   int
}

func (e *InvalidFieldLengthErr) Error() string {
	return fmt.Sprintf("invalid field length, expected %d, got %d", e.Expected, e.Actual)
}

func invalidFieldLengthErr(size, expected int) error {
	return &InvalidFieldLengthErr{
		Expected: expected,
		Actual:   size,
	}
}

type InvalidMultipleOfFieldLengthErr struct {
	Expected int
	Actual   int
}

func (e *InvalidMultipleOfFieldLengthErr) Error() string {
	return fmt.Sprintf("invalid field length, expected multiple of %d, got %d", e.Expected, e.Actual)
}

func invalidMultipleOfFieldLengthErr(size, expected int) error {
	return &InvalidMultipleOfFieldLengthErr{
		Expected: expected,
		Actual:   size,
	}
}

// FieldAccessor grants access to the underlying buffer of a field
type FieldAccessor interface {
	Name() string
	FullName() string

	// Size returns the expected size of the underlying field or zero, if the field has a dynamic size
	Size() uint32

	// Get returns the underlying memory of the field
	Get(data Data) []byte

	// Set sets value as the new reference for the field; if the FieldAccessor is used for the member of a
	// statically sized payload (for example a member of an eBPF struct), value will be copied to the existing
	// memory instead.
	Set(data Data, value []byte) error

	// IsRequested returns whether the consumer is interested in this field; if not, operators are not required
	// to fill them out
	IsRequested() bool

	// AddSubField adds a new field as member of the current field; be careful when doing this on an existing
	// non-empty field, as that might be dropped on serialization // TODO
	AddSubField(name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error)

	// GetSubFieldsWithTag returns all SubFields matching any given tag
	GetSubFieldsWithTag(tag ...string) []FieldAccessor

	// Parent returns the parent of this field, if this field is a SubField
	Parent() FieldAccessor

	// SubFields returns all existing SubFields of the current field
	SubFields() []FieldAccessor

	// SetHidden marks a field as hidden (by default) - it can still be requested
	SetHidden(hidden bool, recurse bool)

	// Type returns the underlying type of the field
	Type() api.Kind

	// Flags returns the flags of the field
	Flags() uint32

	// Tags returns all tags of the field
	Tags() []string

	// AddTags adds new tags to the field
	AddTags(tags ...string)

	// HasAllTagsOf checks whether the field has all given tags
	HasAllTagsOf(tags ...string) bool

	// HasAnyTagsOf checks whether the field has any of the given tags; if tags is empty, it returns false
	HasAnyTagsOf(tags ...string) bool

	// Annotations returns stored annotations of the field
	Annotations() map[string]string

	// AddAnnotation sets a new annotation for the field
	AddAnnotation(key, value string)

	// RemoveReference removes the reference by name from the hierarchy, effectively freeing the name
	// tbd: name
	RemoveReference(recurse bool)

	// Rename changes the name of the field. Currently it's not supported for subfields.
	Rename(string) error

	Uint8(Data) (uint8, error)
	Uint16(Data) (uint16, error)
	Uint32(Data) (uint32, error)
	Uint64(Data) (uint64, error)
	Int8(Data) (int8, error)
	Int16(Data) (int16, error)
	Int32(Data) (int32, error)
	Int64(Data) (int64, error)
	Float32(Data) (float32, error)
	Float64(Data) (float64, error)
	String(Data) (string, error)
	Bytes(Data) ([]byte, error)
	Bool(Data) (bool, error)

	Uint8Array(Data) ([]uint8, error)
	Uint16Array(Data) ([]uint16, error)
	Uint32Array(Data) ([]uint32, error)
	Uint64Array(Data) ([]uint64, error)
	Int8Array(Data) ([]int8, error)
	Int16Array(Data) ([]int16, error)
	Int32Array(Data) ([]int32, error)
	Int64Array(Data) ([]int64, error)
	Float32Array(Data) ([]float32, error)
	Float64Array(Data) ([]float64, error)
	StringArray(Data) ([]string, error)
	BytesArray(Data) ([][]byte, error)

	PutUint8(Data, uint8) error
	PutUint16(Data, uint16) error
	PutUint32(Data, uint32) error
	PutUint64(Data, uint64) error
	PutInt8(Data, int8) error
	PutInt16(Data, int16) error
	PutInt32(Data, int32) error
	PutInt64(Data, int64) error
	PutFloat32(Data, float32) error
	PutFloat64(Data, float64) error
	PutString(Data, string) error
	PutBytes(Data, []byte) error
	PutBool(Data, bool) error

	PutUint8Array(Data, []uint8) error
	PutUint16Array(Data, []uint16) error
	PutUint32Array(Data, []uint32) error
	PutUint64Array(Data, []uint64) error
	PutInt8Array(Data, []int8) error
	PutInt16Array(Data, []int16) error
	PutInt32Array(Data, []int32) error
	PutInt64Array(Data, []int64) error
	PutFloat32Array(Data, []float32) error
	PutFloat64Array(Data, []float64) error
	PutStringArray(Data, []string) error
	PutBytesArray(Data, [][]byte) error

	// StringForColumn returns a human-readable string representation
	// of the field value, suitable for column/table display.
	// This is called by the columns system at display time.
	StringForColumn(data Data) string

	// GetStruct returns struct field value as map.
	// Returns error if field is not a struct type.
	GetStruct(data Data) (map[string]any, error)

	// PutStruct sets struct field value from map.
	// Encodes to protobuf wire format.
	PutStruct(data Data, val map[string]any) error

	// GetStructArray returns array of structs.
	GetStructArray(data Data) ([]map[string]any, error)

	// PutStructArray sets array of structs.
	PutStructArray(data Data, val []map[string]any) error

	// StructAccessor returns the typed struct accessor for efficient encoding.
	// Returns nil if the field is not a struct type or has no definition.
	StructAccessor() *proto.StructAccessor

	// EncodeStruct encodes a struct using a callback for typed field setting.
	// More efficient than PutStruct for high-throughput scenarios.
	EncodeStruct(data Data, fn func(b *proto.StructBuilder)) error

	// EncodeStructArray encodes an array of structs using a callback per element.
	// More efficient than PutStructArray for high-throughput scenarios.
	EncodeStructArray(data Data, count int, fn func(idx int, b *proto.StructBuilder)) error
}

type fieldAccessor struct {
	ds *dataSource
	f  *field

	// Cached struct encoder/decoder (lazy init, thread-safe)
	structOnce     sync.Once
	structDef      *proto.StructDef
	structEncoder  *proto.StructEncoder
	structDecoder  *proto.StructDecoder
	structAccessor *proto.StructAccessor
}

func (a *fieldAccessor) Name() string {
	return a.f.Name
}

func (a *fieldAccessor) FullName() string {
	return a.f.FullName
}

func (a *fieldAccessor) Rename(name string) error {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	if _, ok := a.ds.fieldMap[name]; ok {
		return fmt.Errorf("field with name %q already exists", name)
	}

	if a.f.Name != a.f.FullName {
		return errors.New("Rename() not supported for subfields")
	}

	delete(a.ds.fieldMap, a.f.FullName)

	a.f.Name = name
	a.f.FullName = name
	a.ds.fieldMap[name] = a.f

	return nil
}

func (a *fieldAccessor) Size() uint32 {
	return a.f.Size
}

func (a *fieldAccessor) Type() api.Kind {
	return a.f.Kind
}

func (a *fieldAccessor) Get(d Data) []byte {
	if FieldFlagEmpty.In(a.f.Flags) {
		return nil
	}
	if a.f.Size > 0 {
		// size and offset must be valid here; checks take place on initialization
		return d.payload()[a.f.PayloadIndex][a.f.Offs : a.f.Offs+a.f.Size]
	}
	return d.payload()[a.f.PayloadIndex]
}

func (a *fieldAccessor) setHidden(hidden bool, recurse bool) {
	if !hidden {
		FieldFlagHidden.RemoveFrom(&a.f.Flags)
	} else {
		FieldFlagHidden.AddTo(&a.f.Flags)
	}
	if recurse {
		for _, acc := range a.subFields() {
			acc.(*fieldAccessor).setHidden(hidden, recurse)
		}
	}
}

func (a *fieldAccessor) SetHidden(hidden bool, recurse bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	a.setHidden(hidden, recurse)
}

func (a *fieldAccessor) Set(d Data, b []byte) error {
	if FieldFlagEmpty.In(a.f.Flags) {
		return errors.New("field cannot contain a value")
	}
	if FieldFlagStaticMember.In(a.f.Flags) {
		// If it's a short string copy it and clean the rest with 0s
		if (a.f.Kind == api.Kind_String || a.f.Kind == api.Kind_CString) && uint32(len(b)) < a.f.Size {
			copy(d.payload()[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)

			for i := uint32(len(b)); i < a.f.Size; i++ {
				d.payload()[a.f.PayloadIndex][a.f.Offs+i] = 0
			}
			return nil
		}

		if uint32(len(b)) != a.f.Size {
			return invalidFieldLengthErr(len(b), int(a.f.Size))
		}
		// When accessing a member of a statically sized field, copy memory
		copy(d.payload()[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], b)
		return nil
	}
	if FieldFlagContainer.In(a.f.Flags) {
		if uint32(len(b)) != a.f.Size {
			return invalidFieldLengthErr(len(b), int(a.f.Size))
		}
	}
	d.payload()[a.f.PayloadIndex] = b
	return nil
}

func (a *fieldAccessor) removeReference(recurse bool) {
	// Add flag and remove from fieldMap
	FieldFlagUnreferenced.AddTo(&a.f.Flags)
	delete(a.ds.fieldMap, a.f.FullName)
	if recurse {
		for _, acc := range a.subFields() {
			acc.(*fieldAccessor).removeReference(recurse)
		}
	}
}

func (a *fieldAccessor) RemoveReference(recurse bool) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	a.removeReference(recurse)
}

func (a *fieldAccessor) AddSubField(name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()

	parentFullName, err := resolveNames(a.f.Index, a.ds.fields, 0)
	if err != nil {
		return nil, fmt.Errorf("resolving parent field name: %w", err)
	}

	nf := &field{
		Name:        name,
		FullName:    parentFullName + "." + name,
		Kind:        kind,
		Parent:      a.f.Index,
		Index:       uint32(len(a.ds.fields)),
		Annotations: maps.Clone(defaultFieldAnnotations),
	}
	for _, opt := range opts {
		opt(nf)
	}

	if _, ok := a.ds.fieldMap[nf.FullName]; ok {
		return nil, fmt.Errorf("field with name %q already exists", nf.FullName)
	}

	FieldFlagHasParent.AddTo(&nf.Flags)

	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = a.ds.payloadCount
		a.ds.payloadCount++
	}

	a.ds.applyFieldConfig(nf)

	a.ds.fields = append(a.ds.fields, nf)
	a.ds.fieldMap[nf.FullName] = nf
	return &fieldAccessor{ds: a.ds, f: nf}, nil
}

func (a *fieldAccessor) subFields() []FieldAccessor {
	var res []FieldAccessor
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		res = append(res, &fieldAccessor{
			ds: a.ds,
			f:  f,
		})
	}
	return res
}

func (a *fieldAccessor) SubFields() []FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()
	return a.subFields()
}

func (a *fieldAccessor) Parent() FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()

	if !FieldFlagHasParent.In(a.f.Flags) {
		return nil
	}
	if a.f.Parent >= uint32(len(a.ds.fields)) {
		return nil
	}
	return &fieldAccessor{ds: a.ds, f: a.ds.fields[a.f.Parent]}
}

func (a *fieldAccessor) GetSubFieldsWithTag(tag ...string) []FieldAccessor {
	a.ds.lock.RLock()
	defer a.ds.lock.RUnlock()

	res := make([]FieldAccessor, 0)
	for _, f := range a.ds.fields {
		if !FieldFlagHasParent.In(f.Flags) {
			continue
		}
		if f.Parent != a.f.Index {
			continue
		}
		for _, t := range tag {
			if slices.Contains(f.Tags, t) {
				res = append(res, &fieldAccessor{ds: a.ds, f: f})
				break
			}
		}
	}
	return res
}

func (a *fieldAccessor) IsRequested() bool {
	return a.ds.IsRequestedField(a.f.Name)
}

func (a *fieldAccessor) Flags() uint32 {
	return a.f.Flags
}

func (a *fieldAccessor) Tags() []string {
	return slices.Clone(a.f.Tags)
}

func (a *fieldAccessor) AddTags(tags ...string) {
	a.ds.lock.Lock()
	defer a.ds.lock.Unlock()
	a.f.Tags = append(a.f.Tags, tags...)
}

func (a *fieldAccessor) HasAllTagsOf(tags ...string) bool {
	for _, tag := range tags {
		if !slices.Contains(a.f.Tags, tag) {
			return false
		}
	}
	return true
}

func (a *fieldAccessor) HasAnyTagsOf(tags ...string) bool {
	for _, tag := range tags {
		if slices.Contains(a.f.Tags, tag) {
			return true
		}
	}
	return false
}

func (a *fieldAccessor) Annotations() map[string]string {
	if a.f.Annotations == nil {
		// Return an empty map to allow access without prior checks
		return map[string]string{}
	}
	// return a clone to avoid write access
	return maps.Clone(a.f.Annotations)
}

func (a *fieldAccessor) AddAnnotation(key, value string) {
	if a.f.Annotations == nil {
		a.f.Annotations = map[string]string{}
	}
	a.f.Annotations[key] = value
}

// ElementKind returns the Kind of array elements, or Kind_Invalid if not an array
func (a *fieldAccessor) ElementKind() api.Kind {
	if !api.IsArrayKind(a.f.Kind) {
		return api.Kind_Invalid
	}

	// Check annotation first
	if elemKindStr, ok := a.f.Annotations[AnnotationElementKind]; ok {
		// Parse string to Kind enum value
		// For now, we rely on the bit-flag approach for scalar arrays
		_ = elemKindStr
	}

	// For scalar arrays using bit-flag approach, extract base kind
	return a.f.Kind &^ api.KindFlagArray
}

// IsProtobufEncoded returns true if field uses protobuf wire format
func (a *fieldAccessor) IsProtobufEncoded() bool {
	// Fields with dynamic size flag use protobuf encoding
	if FieldFlagDynamicSize.In(a.f.Flags) {
		return true
	}

	// Struct types always use protobuf encoding
	if a.f.Kind == api.Kind_Kind_Struct || a.f.Kind == api.Kind_Kind_StructArray {
		return true
	}

	return false
}

func (a *fieldAccessor) Uint8(data Data) (uint8, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return 0, invalidFieldLengthErr(len(val), 1)
	}
	return val[0], nil
}

func (a *fieldAccessor) Uint16(data Data) (uint16, error) {
	val := a.Get(data)
	if len(val) != 2 {
		return 0, invalidFieldLengthErr(len(val), 2)
	}
	return a.ds.byteOrder.Uint16(val), nil
}

func (a *fieldAccessor) Uint32(data Data) (uint32, error) {
	val := a.Get(data)
	if len(val) != 4 {
		return 0, invalidFieldLengthErr(len(val), 4)
	}
	return a.ds.byteOrder.Uint32(val), nil
}

func (a *fieldAccessor) Uint64(data Data) (uint64, error) {
	val := a.Get(data)
	if len(val) != 8 {
		return 0, invalidFieldLengthErr(len(val), 8)
	}
	return a.ds.byteOrder.Uint64(val), nil
}

func (a *fieldAccessor) Int8(data Data) (int8, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return 0, invalidFieldLengthErr(len(val), 1)
	}
	return int8(val[0]), nil
}

func (a *fieldAccessor) Int16(data Data) (int16, error) {
	val := a.Get(data)
	if len(val) != 2 {
		return 0, invalidFieldLengthErr(len(val), 2)
	}
	return int16(a.ds.byteOrder.Uint16(val)), nil
}

func (a *fieldAccessor) Int32(data Data) (int32, error) {
	val := a.Get(data)
	if len(val) != 4 {
		return 0, invalidFieldLengthErr(len(val), 4)
	}
	return int32(a.ds.byteOrder.Uint32(val)), nil
}

func (a *fieldAccessor) Int64(data Data) (int64, error) {
	val := a.Get(data)
	if len(val) != 8 {
		return 0, invalidFieldLengthErr(len(val), 8)
	}
	return int64(a.ds.byteOrder.Uint64(val)), nil
}

func (a *fieldAccessor) Float32(data Data) (float32, error) {
	i, err := a.Uint32(data)
	if err != nil {
		return 0.0, err
	}
	return math.Float32frombits(i), nil
}

func (a *fieldAccessor) Float64(data Data) (float64, error) {
	i, err := a.Uint64(data)
	if err != nil {
		return 0.0, err
	}
	return math.Float64frombits(i), nil
}

// Array functions

func copyArray[T constraints.Integer | constraints.Float](a *fieldAccessor, data Data, convert func([]byte) T) ([]T, error) {
	var s T
	size := int(unsafe.Sizeof(s))
	val := a.Get(data)
	if len(val)%size != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), size)
	}
	res := make([]T, 0, len(val)/size)
	for i := 0; i < len(val); i += size {
		res = append(res, convert(val[i:i+size]))
	}
	return res, nil
}

func (a *fieldAccessor) Uint8Array(data Data) ([]uint8, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded (though uint8 is just bytes)
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// For uint8 arrays, they're stored as raw bytes, not protobuf encoded
		return val, nil
	}

	// Static array: already bytes, return directly
	return val, nil
}

func (a *fieldAccessor) Uint16Array(data Data) ([]uint16, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []uint16{}, nil
		}
		arr32, err := proto.DecodeUint32Array(val)
		if err != nil {
			return nil, err
		}
		// Convert uint32 back to uint16
		result := make([]uint16, len(arr32))
		for i, v := range arr32 {
			result[i] = uint16(v)
		}
		return result, nil
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []uint16{}, nil
	}
	if len(val)%2 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 2)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as uint16 slice
		// WARNING: Slice is only valid until callback returns!
		return unsafe.Slice((*uint16)(unsafe.Pointer(&val[0])), len(val)/2), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, a.ds.byteOrder.Uint16)
}

func (a *fieldAccessor) Uint32Array(data Data) ([]uint32, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []uint32{}, nil
		}
		return proto.DecodeUint32Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []uint32{}, nil
	}
	if len(val)%4 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 4)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as uint32 slice
		// WARNING: Slice is only valid until callback returns!
		return unsafe.Slice((*uint32)(unsafe.Pointer(&val[0])), len(val)/4), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, a.ds.byteOrder.Uint32)
}

func (a *fieldAccessor) Uint64Array(data Data) ([]uint64, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []uint64{}, nil
		}
		return proto.DecodeUint64Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []uint64{}, nil
	}
	if len(val)%8 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 8)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as uint64 slice
		// WARNING: Slice is only valid until callback returns!
		return unsafe.Slice((*uint64)(unsafe.Pointer(&val[0])), len(val)/8), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, a.ds.byteOrder.Uint64)
}

func (a *fieldAccessor) Int8Array(data Data) ([]int8, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded (stored as bytes)
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays
		if len(val) == 0 {
			return []int8{}, nil
		}
		result := make([]int8, len(val))
		for i, v := range val {
			result[i] = int8(v)
		}
		return result, nil
	}

	// Static array: zero-copy reinterpret
	if len(val) == 0 {
		return []int8{}, nil
	}
	return unsafe.Slice((*int8)(unsafe.Pointer(&val[0])), len(val)), nil
}

func (a *fieldAccessor) Int16Array(data Data) ([]int16, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []int16{}, nil
		}
		arr32, err := proto.DecodeInt32Array(val)
		if err != nil {
			return nil, err
		}
		// Convert int32 back to int16
		result := make([]int16, len(arr32))
		for i, v := range arr32 {
			result[i] = int16(v)
		}
		return result, nil
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []int16{}, nil
	}
	if len(val)%2 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 2)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as int16 slice
		return unsafe.Slice((*int16)(unsafe.Pointer(&val[0])), len(val)/2), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, func(v []byte) int16 { return int16(a.ds.byteOrder.Uint16(v)) })
}

func (a *fieldAccessor) Int32Array(data Data) ([]int32, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []int32{}, nil
		}
		return proto.DecodeInt32Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []int32{}, nil
	}
	if len(val)%4 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 4)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as int32 slice
		return unsafe.Slice((*int32)(unsafe.Pointer(&val[0])), len(val)/4), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, func(v []byte) int32 { return int32(a.ds.byteOrder.Uint32(v)) })
}

func (a *fieldAccessor) Int64Array(data Data) ([]int64, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []int64{}, nil
		}
		return proto.DecodeInt64Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []int64{}, nil
	}
	if len(val)%8 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 8)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as int64 slice
		return unsafe.Slice((*int64)(unsafe.Pointer(&val[0])), len(val)/8), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, func(v []byte) int64 { return int64(a.ds.byteOrder.Uint64(v)) })
}

func (a *fieldAccessor) Float32Array(data Data) ([]float32, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []float32{}, nil
		}
		return proto.DecodeFloat32Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []float32{}, nil
	}
	if len(val)%4 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 4)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as float32 slice
		return unsafe.Slice((*float32)(unsafe.Pointer(&val[0])), len(val)/4), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, func(v []byte) float32 { return math.Float32frombits(a.ds.byteOrder.Uint32(v)) })
}

func (a *fieldAccessor) Float64Array(data Data) ([]float64, error) {
	val := a.Get(data)

	// Dynamic array: protobuf encoded
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Handle empty arrays (encoder returns nil for empty slices)
		if len(val) == 0 {
			return []float64{}, nil
		}
		return proto.DecodeFloat64Array(val)
	}

	// Static array: check byte order for zero-copy possibility
	if len(val) == 0 {
		return []float64{}, nil
	}
	if len(val)%8 != 0 {
		return nil, invalidMultipleOfFieldLengthErr(len(val), 8)
	}

	if a.ds.byteOrder == binary.NativeEndian {
		// Zero-copy: reinterpret bytes as float64 slice
		return unsafe.Slice((*float64)(unsafe.Pointer(&val[0])), len(val)/8), nil
	}

	// Foreign byte order: must copy and convert
	return copyArray(a, data, func(v []byte) float64 { return math.Float64frombits(a.ds.byteOrder.Uint64(v)) })
}

func (a *fieldAccessor) StringArray(data Data) ([]string, error) {
	val := a.Get(data)

	// String arrays always use protobuf encoding
	// Handle empty arrays (encoder returns nil for empty slices)
	if len(val) == 0 {
		return []string{}, nil
	}
	return proto.DecodeStringArray(val)
}

func (a *fieldAccessor) BytesArray(data Data) ([][]byte, error) {
	val := a.Get(data)

	// Bytes arrays always use protobuf encoding
	// Handle empty arrays (encoder returns nil for empty slices)
	if len(val) == 0 {
		return [][]byte{}, nil
	}
	return proto.DecodeBytesArray(val)
}

func (a *fieldAccessor) String(data Data) (string, error) {
	if a.f.Kind == api.Kind_CString {
		in := a.Get(data)
		for i := 0; i < len(in); i++ {
			if in[i] == 0 {
				return string(in[:i]), nil
			}
		}
		return string(in), nil
	}
	return string(a.Get(data)), nil
}

func (a *fieldAccessor) Bytes(data Data) ([]byte, error) {
	return a.Get(data), nil
}

func (a *fieldAccessor) Bool(data Data) (bool, error) {
	val := a.Get(data)
	if len(val) != 1 {
		return false, invalidFieldLengthErr(len(val), 1)
	}
	return val[0] == 1, nil
}

func (a *fieldAccessor) PutUint8(data Data, val uint8) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}
	b[0] = val
	return nil
}

func (a *fieldAccessor) PutUint16(data Data, val uint16) error {
	b := a.Get(data)
	if len(b) != 2 {
		return invalidFieldLengthErr(len(b), 2)
	}
	a.ds.byteOrder.PutUint16(b, val)
	return nil
}

func (a *fieldAccessor) PutUint32(data Data, val uint32) error {
	b := a.Get(data)
	if len(b) != 4 {
		return invalidFieldLengthErr(len(b), 4)
	}
	a.ds.byteOrder.PutUint32(b, val)
	return nil
}

func (a *fieldAccessor) PutUint64(data Data, val uint64) error {
	b := a.Get(data)
	if len(b) != 8 {
		return invalidFieldLengthErr(len(b), 8)
	}
	a.ds.byteOrder.PutUint64(a.Get(data), val)
	return nil
}

func (a *fieldAccessor) PutInt8(data Data, val int8) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}
	b[0] = uint8(val)
	return nil
}

func (a *fieldAccessor) PutInt16(data Data, val int16) error {
	b := a.Get(data)
	if len(b) != 2 {
		return invalidFieldLengthErr(len(b), 2)
	}
	a.ds.byteOrder.PutUint16(b, uint16(val))
	return nil
}

func (a *fieldAccessor) PutInt32(data Data, val int32) error {
	b := a.Get(data)
	if len(b) != 4 {
		return invalidFieldLengthErr(len(b), 4)
	}
	a.ds.byteOrder.PutUint32(b, uint32(val))
	return nil
}

func (a *fieldAccessor) PutInt64(data Data, val int64) error {
	b := a.Get(data)
	if len(b) != 8 {
		return invalidFieldLengthErr(len(b), 8)
	}
	a.ds.byteOrder.PutUint64(b, uint64(val))
	return nil
}

func (a *fieldAccessor) PutFloat32(data Data, val float32) error {
	return a.PutUint32(data, math.Float32bits(val))
}

func (a *fieldAccessor) PutFloat64(data Data, val float64) error {
	return a.PutUint64(data, math.Float64bits(val))
}

func (a *fieldAccessor) PutString(data Data, val string) error {
	return a.Set(data, []byte(val))
}

func (a *fieldAccessor) PutBytes(data Data, val []byte) error {
	return a.Set(data, val)
}

func (a *fieldAccessor) PutBool(data Data, val bool) error {
	b := a.Get(data)
	if len(b) != 1 {
		return invalidFieldLengthErr(len(b), 1)
	}

	if val {
		b[0] = 1
	} else {
		b[0] = 0
	}
	return nil
}

// Array setters

// putFixedArray copies array data for fixed-size arrays
func putFixedArray[T any](a *fieldAccessor, data Data, val []T) error {
	var t T
	elemSize := int(unsafe.Sizeof(t))
	expectedSize := len(val) * elemSize

	payload := data.payload()
	if a.f.PayloadIndex >= uint32(len(payload)) {
		return fmt.Errorf("payload index out of range")
	}

	// For static members, verify size matches
	if FieldFlagStaticMember.In(a.f.Flags) {
		if uint32(expectedSize) != a.f.Size {
			return invalidFieldLengthErr(expectedSize, int(a.f.Size))
		}
	}

	// Allocate or verify buffer
	if len(payload[a.f.PayloadIndex]) != expectedSize {
		if FieldFlagStaticMember.In(a.f.Flags) {
			return invalidFieldLengthErr(len(payload[a.f.PayloadIndex]), expectedSize)
		}
		payload[a.f.PayloadIndex] = make([]byte, expectedSize)
	}

	// Copy data with byte order conversion
	buf := payload[a.f.PayloadIndex]
	for i, v := range val {
		offset := i * elemSize
		// Use unsafe to get raw bytes, then copy with proper byte order
		valBytes := (*[1 << 30]byte)(unsafe.Pointer(&v))[:elemSize:elemSize]
		copy(buf[offset:offset+elemSize], valBytes)
	}

	return nil
}

func (a *fieldAccessor) PutUint8Array(data Data, val []uint8) error {
	// Uint8 arrays are just byte slices, stored directly (no protobuf encoding needed)
	if FieldFlagDynamicSize.In(a.f.Flags) {
		return a.Set(data, val)
	}

	// Fixed-size array: direct byte copy (uint8 = byte)
	payload := data.payload()
	if a.f.PayloadIndex >= uint32(len(payload)) {
		return fmt.Errorf("payload index out of range")
	}

	if FieldFlagStaticMember.In(a.f.Flags) {
		if uint32(len(val)) != a.f.Size {
			return invalidFieldLengthErr(len(val), int(a.f.Size))
		}
		copy(payload[a.f.PayloadIndex][a.f.Offs:a.f.Offs+a.f.Size], val)
		return nil
	}

	payload[a.f.PayloadIndex] = val
	return nil
}

func (a *fieldAccessor) PutUint16Array(data Data, val []uint16) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		// Convert to uint32 for protobuf encoding (protowire doesn't have uint16)
		val32 := make([]uint32, len(val))
		for i, v := range val {
			val32[i] = uint32(v)
		}
		encoder := proto.NewArrayEncoder(len(val)*4 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeUint32Array(1, val32)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutUint32Array(data Data, val []uint32) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*4 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeUint32Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutUint64Array(data Data, val []uint64) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*8 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeUint64Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutInt8Array(data Data, val []int8) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: convert to []byte and set directly
		b := make([]byte, len(val))
		for i, v := range val {
			b[i] = byte(v)
		}
		return a.Set(data, b)
	}

	// Fixed-size array: direct byte copy
	payload := data.payload()
	if a.f.PayloadIndex >= uint32(len(payload)) {
		return fmt.Errorf("payload index out of range")
	}

	if FieldFlagStaticMember.In(a.f.Flags) {
		if uint32(len(val)) != a.f.Size {
			return invalidFieldLengthErr(len(val), int(a.f.Size))
		}
		for i, v := range val {
			payload[a.f.PayloadIndex][a.f.Offs+uint32(i)] = byte(v)
		}
		return nil
	}

	b := make([]byte, len(val))
	for i, v := range val {
		b[i] = byte(v)
	}
	payload[a.f.PayloadIndex] = b
	return nil
}

func (a *fieldAccessor) PutInt16Array(data Data, val []int16) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		val32 := make([]int32, len(val))
		for i, v := range val {
			val32[i] = int32(v)
		}
		encoder := proto.NewArrayEncoder(len(val)*4 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeInt32Array(1, val32)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutInt32Array(data Data, val []int32) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*4 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeInt32Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutInt64Array(data Data, val []int64) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*8 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeInt64Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutFloat32Array(data Data, val []float32) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*4 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeFloat32Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutFloat64Array(data Data, val []float64) error {
	if FieldFlagDynamicSize.In(a.f.Flags) {
		// Dynamic array: encode with protobuf
		encoder := proto.NewArrayEncoder(len(val)*8 + proto.ProtoHeaderOverhead)
		encoded := encoder.EncodeFloat64Array(1, val)
		return a.Set(data, encoded)
	}

	// Fixed-size array: use putFixedArray
	return putFixedArray(a, data, val)
}

func (a *fieldAccessor) PutStringArray(data Data, val []string) error {
	// String arrays always use protobuf encoding (no fixed-size version)
	encoder := proto.NewArrayEncoder(proto.DefaultEncoderCapacity)
	encoded := encoder.EncodeStringArray(1, val)
	return a.Set(data, encoded)
}

func (a *fieldAccessor) PutBytesArray(data Data, val [][]byte) error {
	// Bytes arrays always use protobuf encoding (no fixed-size version)
	encoder := proto.NewArrayEncoder(proto.DefaultEncoderCapacity)
	encoded := encoder.EncodeBytesArray(1, val)
	return a.Set(data, encoded)
}

// StringForColumn returns a human-readable string representation
// of the field value, suitable for column/table display.
// This is called by the columns system at display time.
func (a *fieldAccessor) StringForColumn(data Data) string {
	if api.IsArrayKind(a.f.Kind) {
		return a.formatArrayForColumn(data)
	}
	if a.f.Kind == api.Kind_Kind_Struct || a.f.Kind == api.Kind_Kind_StructArray {
		return a.formatStructForColumn(data)
	}
	// Fallback: use standard string conversion
	return fmt.Sprintf("%v", a.Get(data))
}

func (a *fieldAccessor) formatArrayForColumn(data Data) string {
	elemKind := a.f.Kind &^ api.KindFlagArray

	switch elemKind {
	case api.Kind_Uint8:
		arr, err := a.Uint8Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Uint16:
		arr, err := a.Uint16Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Uint32:
		arr, err := a.Uint32Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Uint64:
		arr, err := a.Uint64Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Int8:
		arr, err := a.Int8Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Int16:
		arr, err := a.Int16Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Int32:
		arr, err := a.Int32Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Int64:
		arr, err := a.Int64Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Float32:
		arr, err := a.Float32Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_Float64:
		arr, err := a.Float64Array(data)
		if err != nil {
			return "[]"
		}
		return formatNumericArray(arr)
	case api.Kind_String:
		arr, err := a.StringArray(data)
		if err != nil {
			return "[]"
		}
		return formatStringArrayForColumn(arr)
	default:
		// Unknown element type: show byte count
		return fmt.Sprintf("[%d bytes]", len(a.Get(data)))
	}
}

func (a *fieldAccessor) formatStructForColumn(data Data) string {
	switch a.f.Kind {
	case api.Kind_Kind_Struct:
		m, err := a.GetStruct(data)
		if err != nil {
			return "{error}"
		}
		return formatStructMap(m)
	case api.Kind_Kind_StructArray:
		arr, err := a.GetStructArray(data)
		if err != nil {
			return "[error]"
		}
		return formatStructArrayForColumn(arr)
	default:
		return "{struct}"
	}
}

// formatStructMap formats a struct map for display
func formatStructMap(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	// For columns, show abbreviated version
	if len(m) > 3 {
		return fmt.Sprintf("{%d fields}", len(m))
	}
	return fmt.Sprintf("%v", m)
}

// formatStructArrayForColumn formats an array of structs for column display
func formatStructArrayForColumn(arr []map[string]any) string {
	if len(arr) == 0 {
		return "[]"
	}
	if len(arr) <= 2 {
		return fmt.Sprintf("%v", arr)
	}
	return fmt.Sprintf("[{...},...] (%d)", len(arr))
}

// formatNumericArray formats numeric arrays for column display
func formatNumericArray[T constraints.Integer | constraints.Float](arr []T) string {
	if len(arr) == 0 {
		return "[]"
	}
	if len(arr) <= 5 {
		// Short array: show all values
		return fmt.Sprintf("%v", arr)
	}
	// Long array: show summary
	return fmt.Sprintf("[%v,...,%v] (%d)", arr[0], arr[len(arr)-1], len(arr))
}

func formatStringArrayForColumn(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	if len(arr) <= 3 {
		return fmt.Sprintf("%q", arr)
	}
	return fmt.Sprintf("[%q,...] (%d)", arr[0], len(arr))
}

// initStructCodecs initializes the struct encoder/decoder from field annotations.
// This is called lazily on first use and is thread-safe.
func (a *fieldAccessor) initStructCodecs() {
	a.structOnce.Do(func() {
		// Check for struct definition in annotations
		defValue, ok := a.f.Annotations[AnnotationStructFields]
		if !ok {
			return
		}

		def, err := proto.ParseSchemaAnnotation(defValue)
		if err != nil {
			return
		}

		a.structDef = def

		// Create the typed accessor (includes encoder/decoder)
		accessor, err := proto.NewStructAccessor(def)
		if err == nil {
			a.structAccessor = accessor
			a.structDecoder = accessor.Decoder()
		}

		// Also create legacy encoder for backwards compatibility
		a.structEncoder = proto.NewStructEncoder(def, proto.DefaultEncoderCapacity)

		// Fallback decoder if accessor creation failed
		if a.structDecoder == nil {
			decoder, err := proto.NewStructDecoder(def)
			if err == nil {
				a.structDecoder = decoder
			}
		}
	})
}

// getStructDef returns the cached struct definition, initializing if needed.
func (a *fieldAccessor) getStructDef() *proto.StructDef {
	a.initStructCodecs()
	return a.structDef
}

// getStructEncoder returns the cached struct encoder, initializing if needed.
func (a *fieldAccessor) getStructEncoder() *proto.StructEncoder {
	a.initStructCodecs()
	return a.structEncoder
}

// getStructDecoder returns the cached struct decoder, initializing if needed.
func (a *fieldAccessor) getStructDecoder() *proto.StructDecoder {
	a.initStructCodecs()
	return a.structDecoder
}

// GetStruct returns struct field value as map.
// Returns error if field is not a struct type.
func (a *fieldAccessor) GetStruct(data Data) (map[string]any, error) {
	if a.f.Kind != api.Kind_Kind_Struct {
		return nil, fmt.Errorf("field %s is not a struct (kind=%v)", a.f.Name, a.f.Kind)
	}

	decoder := a.getStructDecoder()
	if decoder == nil {
		return nil, fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	return decoder.Decode(a.Get(data))
}

// PutStruct sets struct field value from map.
// Encodes to protobuf wire format.
func (a *fieldAccessor) PutStruct(data Data, val map[string]any) error {
	if a.f.Kind != api.Kind_Kind_Struct {
		return fmt.Errorf("field %s is not a struct (kind=%v)", a.f.Name, a.f.Kind)
	}

	encoder := a.getStructEncoder()
	if encoder == nil {
		return fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	encoded, err := encoder.Encode(val)
	if err != nil {
		return err
	}

	return a.Set(data, encoded)
}

// GetStructArray returns array of structs.
func (a *fieldAccessor) GetStructArray(data Data) ([]map[string]any, error) {
	if a.f.Kind != api.Kind_Kind_StructArray {
		return nil, fmt.Errorf("field %s is not a struct array (kind=%v)", a.f.Name, a.f.Kind)
	}

	decoder := a.getStructDecoder()
	if decoder == nil {
		return nil, fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	return decoder.DecodeStructArray(a.Get(data))
}

// PutStructArray sets array of structs.
func (a *fieldAccessor) PutStructArray(data Data, val []map[string]any) error {
	if a.f.Kind != api.Kind_Kind_StructArray {
		return fmt.Errorf("field %s is not a struct array (kind=%v)", a.f.Name, a.f.Kind)
	}

	encoder := a.getStructEncoder()
	if encoder == nil {
		return fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	encoded, err := encoder.EncodeStructArray(1, val)
	if err != nil {
		return err
	}

	return a.Set(data, encoded)
}

// StructAccessor returns the typed struct accessor for efficient encoding.
// Returns nil if the field is not a struct type or has no definition.
func (a *fieldAccessor) StructAccessor() *proto.StructAccessor {
	a.initStructCodecs()
	return a.structAccessor
}

// EncodeStruct encodes a struct using a callback for typed field setting.
// More efficient than PutStruct for high-throughput scenarios.
func (a *fieldAccessor) EncodeStruct(data Data, fn func(b *proto.StructBuilder)) error {
	if a.f.Kind != api.Kind_Kind_Struct {
		return fmt.Errorf("field %s is not a struct (kind=%v)", a.f.Name, a.f.Kind)
	}

	accessor := a.StructAccessor()
	if accessor == nil {
		return fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	encoded := accessor.EncodeCallback(fn)
	return a.Set(data, encoded)
}

// EncodeStructArray encodes an array of structs using a callback per element.
// More efficient than PutStructArray for high-throughput scenarios.
func (a *fieldAccessor) EncodeStructArray(data Data, count int, fn func(idx int, b *proto.StructBuilder)) error {
	if a.f.Kind != api.Kind_Kind_StructArray {
		return fmt.Errorf("field %s is not a struct array (kind=%v)", a.f.Name, a.f.Kind)
	}

	accessor := a.StructAccessor()
	if accessor == nil {
		return fmt.Errorf("no struct definition for field %s", a.f.Name)
	}

	encoded := accessor.EncodeStructArrayCallback(1, count, fn)
	return a.Set(data, encoded)
}
