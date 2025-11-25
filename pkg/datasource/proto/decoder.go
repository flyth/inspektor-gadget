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
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

var (
	// ErrInvalidWireFormat is returned when the wire format is malformed
	ErrInvalidWireFormat = errors.New("invalid protobuf wire format")

	// ErrUnexpectedWireType is returned when the wire type doesn't match expected
	ErrUnexpectedWireType = errors.New("unexpected wire type")
)

// DecodeUint32Array decodes a packed repeated uint32 field.
// Expects data encoded with fixed32 encoding (4 bytes per element).
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeUint32Array(data []byte) ([]uint32, error) {
	return DecodePackedArray(data, Uint32Codec)
}

// DecodeUint64Array decodes a packed repeated uint64 field.
// Expects data encoded with fixed64 encoding (8 bytes per element).
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeUint64Array(data []byte) ([]uint64, error) {
	return DecodePackedArray(data, Uint64Codec)
}

// DecodeInt32Array decodes a packed repeated int32 field.
// Expects data encoded with fixed32 encoding.
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeInt32Array(data []byte) ([]int32, error) {
	return DecodePackedArray(data, Int32Codec)
}

// DecodeInt64Array decodes a packed repeated int64 field.
// Expects data encoded with fixed64 encoding.
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeInt64Array(data []byte) ([]int64, error) {
	return DecodePackedArray(data, Int64Codec)
}

// DecodeFloat32Array decodes a packed repeated float32 field.
// Expects data encoded with fixed32 encoding (IEEE 754 binary32).
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeFloat32Array(data []byte) ([]float32, error) {
	return DecodePackedArray(data, Float32Codec)
}

// DecodeFloat64Array decodes a packed repeated float64 field.
// Expects data encoded with fixed64 encoding (IEEE 754 binary64).
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeFloat64Array(data []byte) ([]float64, error) {
	return DecodePackedArray(data, Float64Codec)
}

// DecodeStringArray decodes a repeated string field (non-packed).
// Each string is length-delimited.
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeStringArray(data []byte) ([]string, error) {
	if len(data) == 0 {
		return []string{}, nil
	}

	buf := data
	var result []string

	for len(buf) > 0 {
		// Consume tag
		_, wt, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		if wt != protowire.BytesType {
			return nil, ErrUnexpectedWireType
		}
		buf = buf[n:]

		// Consume string bytes
		val, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		result = append(result, string(val))
		buf = buf[n:]
	}

	return result, nil
}

// DecodeBytesArray decodes a repeated bytes field (non-packed).
// Each byte slice is length-delimited.
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodeBytesArray(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return [][]byte{}, nil
	}

	buf := data
	var result [][]byte

	for len(buf) > 0 {
		// Consume tag
		_, wt, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		if wt != protowire.BytesType {
			return nil, ErrUnexpectedWireType
		}
		buf = buf[n:]

		// Consume bytes
		val, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}

		// Make a copy since val is a slice into the original buffer
		valCopy := make([]byte, len(val))
		copy(valCopy, val)
		result = append(result, valCopy)
		buf = buf[n:]
	}

	return result, nil
}

// StructDecoder decodes protobuf wire format to Go maps based on a StructDef.
// It uses dynamicpb with cached descriptors for efficient decoding.
type StructDecoder struct {
	def  *StructDef
	desc protoreflect.MessageDescriptor
}

// NewStructDecoder creates a new StructDecoder for a specific struct definition.
// It pre-builds the protobuf descriptor for efficient decoding.
func NewStructDecoder(def *StructDef) (*StructDecoder, error) {
	desc, err := def.ToProtoDescriptor()
	if err != nil {
		return nil, fmt.Errorf("building protobuf descriptor: %w", err)
	}
	return &StructDecoder{def: def, desc: desc}, nil
}

// Decode decodes protobuf bytes to map[string]any.
// The returned map contains field names as keys and decoded values.
func (d *StructDecoder) Decode(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return make(map[string]any), nil
	}

	// Use dynamicpb with the cached descriptor
	msg := dynamicpb.NewMessage(d.desc)
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("unmarshaling protobuf: %w", err)
	}

	return d.messageToMap(msg)
}

// messageToMap converts a dynamicpb message to map[string]any.
func (d *StructDecoder) messageToMap(msg *dynamicpb.Message) (map[string]any, error) {
	result := make(map[string]any)

	// Iterate through all fields in the struct definition
	for _, fieldDef := range d.def.Fields {
		fd := d.desc.Fields().ByNumber(protoreflect.FieldNumber(fieldDef.FieldNum))
		if fd == nil {
			continue
		}

		// For proto3, check if field is set using Has() for messages/repeated fields
		// For scalars, always include them (even default values) since we use fixed encoding
		hasValue := msg.Has(fd)
		if !hasValue {
			// For message and repeated fields, skip if not set
			if fd.Kind() == protoreflect.MessageKind || fd.IsList() {
				continue
			}
			// For scalars, we still want to include them if they were encoded
			// Check if we have actual data by looking at the value
			// Since we use fixed-width encoding, default values are still encoded
		}

		v := msg.Get(fd)
		value, err := d.fieldToGo(fieldDef, fd, v)
		if err != nil {
			return nil, fmt.Errorf("converting field %s: %w", fieldDef.Name, err)
		}
		result[fieldDef.Name] = value
	}

	return result, nil
}

// fieldToGo converts a protoreflect.Value to a Go value based on the field definition.
func (d *StructDecoder) fieldToGo(fieldDef StructFieldDef, fd protoreflect.FieldDescriptor, v protoreflect.Value) (any, error) {
	switch {
	case fieldDef.Kind == Kind_Kind_Struct:
		// Nested struct - use the message's own descriptor
		nestedMsg, ok := v.Message().Interface().(*dynamicpb.Message)
		if !ok {
			return nil, fmt.Errorf("expected dynamicpb.Message for nested struct")
		}
		return d.nestedMessageToMap(nestedMsg, fieldDef.NestedDef)

	case fieldDef.Kind == Kind_Kind_StructArray:
		// Array of structs
		list := v.List()
		result := make([]map[string]any, list.Len())

		for i := 0; i < list.Len(); i++ {
			item := list.Get(i)
			nestedMsg, ok := item.Message().Interface().(*dynamicpb.Message)
			if !ok {
				return nil, fmt.Errorf("expected dynamicpb.Message at index %d", i)
			}
			m, err := d.nestedMessageToMap(nestedMsg, fieldDef.NestedDef)
			if err != nil {
				return nil, err
			}
			result[i] = m
		}
		return result, nil

	case IsArrayKind(fieldDef.Kind):
		// Array of scalars
		return d.listToSlice(v.List(), fieldDef.ElemKind)

	default:
		// Scalar
		return d.scalarToGo(v, fieldDef.Kind), nil
	}
}

// nestedMessageToMap converts a nested dynamicpb message to map[string]any.
// It uses the message's own descriptor to ensure field descriptor compatibility.
func (d *StructDecoder) nestedMessageToMap(msg *dynamicpb.Message, nestedDef *StructDef) (map[string]any, error) {
	result := make(map[string]any)
	msgDesc := msg.Descriptor()

	for _, fieldDef := range nestedDef.Fields {
		fd := msgDesc.Fields().ByNumber(protoreflect.FieldNumber(fieldDef.FieldNum))
		if fd == nil {
			continue
		}

		// For proto3, check if field is set using Has() for messages/repeated fields
		// For scalars, always include them (even default values) since we use fixed encoding
		hasValue := msg.Has(fd)
		if !hasValue {
			// For message and repeated fields, skip if not set
			if fd.Kind() == protoreflect.MessageKind || fd.IsList() {
				continue
			}
			// For scalars, we still want to include them if they were encoded
		}

		v := msg.Get(fd)
		value, err := d.nestedFieldToGo(fieldDef, fd, v, msg)
		if err != nil {
			return nil, fmt.Errorf("converting field %s: %w", fieldDef.Name, err)
		}
		result[fieldDef.Name] = value
	}

	return result, nil
}

// nestedFieldToGo converts a protoreflect.Value from a nested message to a Go value.
func (d *StructDecoder) nestedFieldToGo(fieldDef StructFieldDef, fd protoreflect.FieldDescriptor, v protoreflect.Value, parentMsg *dynamicpb.Message) (any, error) {
	switch {
	case fieldDef.Kind == Kind_Kind_Struct:
		// Nested struct within nested struct
		nestedMsg, ok := v.Message().Interface().(*dynamicpb.Message)
		if !ok {
			return nil, fmt.Errorf("expected dynamicpb.Message for nested struct")
		}
		return d.nestedMessageToMap(nestedMsg, fieldDef.NestedDef)

	case fieldDef.Kind == Kind_Kind_StructArray:
		// Array of structs within nested struct
		list := v.List()
		result := make([]map[string]any, list.Len())

		for i := 0; i < list.Len(); i++ {
			item := list.Get(i)
			nestedMsg, ok := item.Message().Interface().(*dynamicpb.Message)
			if !ok {
				return nil, fmt.Errorf("expected dynamicpb.Message at index %d", i)
			}
			m, err := d.nestedMessageToMap(nestedMsg, fieldDef.NestedDef)
			if err != nil {
				return nil, err
			}
			result[i] = m
		}
		return result, nil

	case IsArrayKind(fieldDef.Kind):
		// Array of scalars
		return d.listToSlice(v.List(), fieldDef.ElemKind)

	default:
		// Scalar
		return d.scalarToGo(v, fieldDef.Kind), nil
	}
}

// listToSlice converts a protoreflect.List to a typed Go slice.
// Uses map-based dispatch for cleaner code.
func (d *StructDecoder) listToSlice(list protoreflect.List, elemKind Kind) (any, error) {
	if list.Len() == 0 {
		return d.emptySlice(elemKind), nil
	}

	conv := getKindConverter(elemKind)
	if conv == nil {
		return nil, fmt.Errorf("unsupported element kind: %v", elemKind)
	}
	return conv.listToSlice(list), nil
}

// emptySlice returns an empty slice of the appropriate type.
// Uses map-based dispatch for cleaner code.
func (d *StructDecoder) emptySlice(elemKind Kind) any {
	conv := getKindConverter(elemKind)
	if conv == nil {
		return []any{}
	}
	return conv.emptySlice()
}

// scalarToGo converts a protoreflect.Value to a Go scalar value.
// Uses map-based dispatch for cleaner code.
func (d *StructDecoder) scalarToGo(v protoreflect.Value, kind Kind) any {
	conv := getKindConverter(kind)
	if conv == nil {
		return v.Interface()
	}
	return conv.scalarToGo(v)
}

// DecodeStructArray decodes repeated embedded messages to []map[string]any.
// This is for decoding an array of structs encoded at the top level.
func (d *StructDecoder) DecodeStructArray(data []byte) ([]map[string]any, error) {
	if len(data) == 0 {
		return []map[string]any{}, nil
	}

	var result []map[string]any
	buf := data

	for len(buf) > 0 {
		// Consume tag
		_, wt, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		if wt != protowire.BytesType {
			return nil, ErrUnexpectedWireType
		}
		buf = buf[n:]

		// Consume message bytes
		msgBytes, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		buf = buf[n:]

		// Decode the struct
		m, err := d.Decode(msgBytes)
		if err != nil {
			return nil, fmt.Errorf("decoding struct array element: %w", err)
		}
		result = append(result, m)
	}

	return result, nil
}
