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

	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// StructFieldDef describes a field within a struct for protobuf encoding.
type StructFieldDef struct {
	Name      string      // Field name
	Kind      api.Kind    // Field type (scalar, array, or struct)
	FieldNum  int         // Protobuf field number (1-based)
	ElemKind  api.Kind    // For arrays: element type (without array flag)
	NestedDef *StructDef  // For nested structs: the struct definition
}

// StructDef describes a struct type at runtime for protobuf encoding/decoding.
type StructDef struct {
	Name   string
	Fields []StructFieldDef
}

// NewStructDef creates a new StructDef with the given name.
func NewStructDef(name string) *StructDef {
	return &StructDef{
		Name:   name,
		Fields: make([]StructFieldDef, 0),
	}
}

// AddField adds a scalar field to the struct definition.
// Field numbers are assigned sequentially starting from 1.
func (s *StructDef) AddField(name string, kind api.Kind) *StructDef {
	s.Fields = append(s.Fields, StructFieldDef{
		Name:     name,
		Kind:     kind,
		FieldNum: len(s.Fields) + 1,
	})
	return s
}

// AddArrayField adds an array field to the struct definition.
func (s *StructDef) AddArrayField(name string, elemKind api.Kind) *StructDef {
	s.Fields = append(s.Fields, StructFieldDef{
		Name:     name,
		Kind:     api.ArrayOf(elemKind),
		FieldNum: len(s.Fields) + 1,
		ElemKind: elemKind,
	})
	return s
}

// AddNestedField adds a nested struct field to the struct definition.
func (s *StructDef) AddNestedField(name string, nested *StructDef) *StructDef {
	s.Fields = append(s.Fields, StructFieldDef{
		Name:      name,
		Kind:      api.Kind_Kind_Struct,
		FieldNum:  len(s.Fields) + 1,
		NestedDef: nested,
	})
	return s
}

// AddNestedArrayField adds an array of nested structs to the struct definition.
func (s *StructDef) AddNestedArrayField(name string, nested *StructDef) *StructDef {
	s.Fields = append(s.Fields, StructFieldDef{
		Name:      name,
		Kind:      api.Kind_Kind_StructArray,
		FieldNum:  len(s.Fields) + 1,
		NestedDef: nested,
	})
	return s
}

// NewStructDefFromFields creates a StructDef from an api.Field slice.
// This is useful for creating struct definitions from gadget metadata.
func NewStructDefFromFields(name string, fields []*api.Field) (*StructDef, error) {
	def := NewStructDef(name)
	for i, f := range fields {
		fieldDef := StructFieldDef{
			Name:     f.Name,
			Kind:     f.Kind,
			FieldNum: i + 1,
		}

		if api.IsArrayKind(f.Kind) {
			fieldDef.ElemKind = f.Kind & ^api.KindFlagArray
		}

		// For nested structs, we would need to recursively process subfields
		// This is handled by the caller providing nested StructDefs
		def.Fields = append(def.Fields, fieldDef)
	}
	return def, nil
}

// GetFieldByName returns the field definition with the given name, or nil if not found.
func (s *StructDef) GetFieldByName(name string) *StructFieldDef {
	for i := range s.Fields {
		if s.Fields[i].Name == name {
			return &s.Fields[i]
		}
	}
	return nil
}

// GetFieldByNum returns the field definition with the given field number, or nil if not found.
func (s *StructDef) GetFieldByNum(num int) *StructFieldDef {
	for i := range s.Fields {
		if s.Fields[i].FieldNum == num {
			return &s.Fields[i]
		}
	}
	return nil
}

// ToProtoDescriptor generates a protoreflect.MessageDescriptor for this struct definition.
// This enables decoding with dynamicpb.
func (s *StructDef) ToProtoDescriptor() (protoreflect.MessageDescriptor, error) {
	// Build a minimal FileDescriptorProto containing our message
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    stringPtr("dynamic.proto"),
		Package: stringPtr("dynamic"),
		Syntax:  stringPtr("proto3"),
	}

	// Add the message descriptor
	msgDesc, err := s.buildMessageDescriptor()
	if err != nil {
		return nil, err
	}
	fdp.MessageType = append(fdp.MessageType, msgDesc)

	// Build the file descriptor
	fd, err := buildFileDescriptor(fdp)
	if err != nil {
		return nil, fmt.Errorf("building file descriptor: %w", err)
	}

	// Return the message descriptor
	msgs := fd.Messages()
	if msgs.Len() == 0 {
		return nil, fmt.Errorf("no message found in descriptor")
	}
	return msgs.Get(0), nil
}

// buildMessageDescriptor creates a DescriptorProto for this struct definition.
func (s *StructDef) buildMessageDescriptor() (*descriptorpb.DescriptorProto, error) {
	msgDesc := &descriptorpb.DescriptorProto{
		Name: stringPtr(s.Name),
	}

	for _, field := range s.Fields {
		fd, nested, err := s.buildFieldDescriptor(field)
		if err != nil {
			return nil, fmt.Errorf("building field %s: %w", field.Name, err)
		}
		msgDesc.Field = append(msgDesc.Field, fd)
		if nested != nil {
			msgDesc.NestedType = append(msgDesc.NestedType, nested...)
		}
	}

	return msgDesc, nil
}

// buildFieldDescriptor creates a FieldDescriptorProto for a field.
// Returns the field descriptor and any nested message types needed.
func (s *StructDef) buildFieldDescriptor(field StructFieldDef) (*descriptorpb.FieldDescriptorProto, []*descriptorpb.DescriptorProto, error) {
	fd := &descriptorpb.FieldDescriptorProto{
		Name:   stringPtr(field.Name),
		Number: int32Ptr(int32(field.FieldNum)),
	}

	var nestedTypes []*descriptorpb.DescriptorProto

	switch {
	case field.Kind == api.Kind_Kind_Struct:
		// Nested struct
		fd.Type = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
		fd.TypeName = stringPtr(field.NestedDef.Name)

		nested, err := field.NestedDef.buildMessageDescriptor()
		if err != nil {
			return nil, nil, err
		}
		nestedTypes = append(nestedTypes, nested)

	case field.Kind == api.Kind_Kind_StructArray:
		// Array of structs
		fd.Type = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
		fd.TypeName = stringPtr(field.NestedDef.Name)
		fd.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()

		nested, err := field.NestedDef.buildMessageDescriptor()
		if err != nil {
			return nil, nil, err
		}
		nestedTypes = append(nestedTypes, nested)

	case api.IsArrayKind(field.Kind):
		// Array of scalars
		protoType := kindToProtoType(field.ElemKind)
		fd.Type = protoType.Enum()
		fd.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()

	default:
		// Scalar field
		protoType := kindToProtoType(field.Kind)
		fd.Type = protoType.Enum()
	}

	return fd, nestedTypes, nil
}

// kindToProtoType maps api.Kind to protobuf field types.
func kindToProtoType(kind api.Kind) descriptorpb.FieldDescriptorProto_Type {
	// Remove array flag if present
	kind = kind & ^api.KindFlagArray

	switch kind {
	case api.Kind_Bool:
		return descriptorpb.FieldDescriptorProto_TYPE_BOOL
	case api.Kind_Int8, api.Kind_Int16, api.Kind_Int32:
		return descriptorpb.FieldDescriptorProto_TYPE_SFIXED32
	case api.Kind_Int64:
		return descriptorpb.FieldDescriptorProto_TYPE_SFIXED64
	case api.Kind_Uint8, api.Kind_Uint16, api.Kind_Uint32:
		return descriptorpb.FieldDescriptorProto_TYPE_FIXED32
	case api.Kind_Uint64:
		return descriptorpb.FieldDescriptorProto_TYPE_FIXED64
	case api.Kind_Float32:
		return descriptorpb.FieldDescriptorProto_TYPE_FLOAT
	case api.Kind_Float64:
		return descriptorpb.FieldDescriptorProto_TYPE_DOUBLE
	case api.Kind_String, api.Kind_CString:
		return descriptorpb.FieldDescriptorProto_TYPE_STRING
	case api.Kind_Bytes:
		return descriptorpb.FieldDescriptorProto_TYPE_BYTES
	default:
		return descriptorpb.FieldDescriptorProto_TYPE_BYTES
	}
}

// Helper function for string pointers
func stringPtr(s string) *string {
	return &s
}

// Helper function for int32 pointers
func int32Ptr(i int32) *int32 {
	return &i
}

// buildFileDescriptor builds a file descriptor from a FileDescriptorProto.
// Uses protodesc package for proper descriptor building.
func buildFileDescriptor(fdp *descriptorpb.FileDescriptorProto) (protoreflect.FileDescriptor, error) {
	return protodesc.NewFile(fdp, nil)
}
