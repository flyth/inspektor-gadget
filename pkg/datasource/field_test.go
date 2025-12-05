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
	"maps"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/proto"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestDataSourceFieldConfig(t *testing.T) {
	type testCase struct {
		name                string
		expectedAnnotations map[string]string
		expectedFlags       FieldFlag
		config              string
	}

	testCases := []testCase{
		{
			name:   "no-anotations",
			config: "",
		},
		{
			name: "columns.hidden",
			expectedAnnotations: map[string]string{
				"columns.hidden": "true",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.hidden: true
`,
		},
		{
			name: "many-annotations",
			expectedAnnotations: map[string]string{
				"columns.width":    "40",
				"columns.maxwidth": "80",
				"foo-ann":          "yes",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.width: 40
      columns.maxwidth: 80
      foo-ann: yes
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tc.config))
			require.NoError(t, err)

			ds, err := New(TypeArray, "myds", WithConfig(v))
			require.NoError(t, err)

			fooAcc, err := ds.AddField("foo", api.Kind_String)
			require.NoError(t, err)

			expectedAnnotations := maps.Clone(defaultFieldAnnotations)
			maps.Copy(expectedAnnotations, tc.expectedAnnotations)

			assert.Equal(t, fooAcc.Annotations(), expectedAnnotations)
		})
	}
}

func TestStructFieldAccessor(t *testing.T) {
	// Create struct definition
	def := proto.NewStructDef("TestStruct").
		AddField("pid", api.Kind_Uint32).
		AddField("comm", api.Kind_String).
		AddField("timestamp", api.Kind_Uint64)

	defSchema, err := def.SerializeSchema()
	require.NoError(t, err)

	// Create datasource with struct field
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	structField, err := ds.AddField("data", api.Kind_Kind_Struct,
		WithFlags(FieldFlagDynamicSize),
		WithAnnotation(AnnotationStructFields, defSchema))
	require.NoError(t, err)

	// Create data and test round-trip
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// Test PutStruct/GetStruct
	input := map[string]any{
		"pid":       uint32(1234),
		"comm":      "test-process",
		"timestamp": uint64(9999999),
	}

	err = structField.PutStruct(data, input)
	require.NoError(t, err)

	output, err := structField.GetStruct(data)
	require.NoError(t, err)

	assert.Equal(t, input["pid"], output["pid"])
	assert.Equal(t, input["comm"], output["comm"])
	assert.Equal(t, input["timestamp"], output["timestamp"])
}

func TestStructArrayFieldAccessor(t *testing.T) {
	// Create struct definition
	def := proto.NewStructDef("ProcessInfo").
		AddField("pid", api.Kind_Uint32).
		AddField("comm", api.Kind_String)

	defSchema, err := def.SerializeSchema()
	require.NoError(t, err)

	// Create datasource with struct array field
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	structArrayField, err := ds.AddField("processes", api.Kind_Kind_StructArray,
		WithFlags(FieldFlagDynamicSize),
		WithAnnotation(AnnotationStructFields, defSchema))
	require.NoError(t, err)

	// Create data and test round-trip
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// Test PutStructArray/GetStructArray
	input := []map[string]any{
		{"pid": uint32(1), "comm": "init"},
		{"pid": uint32(2), "comm": "kthreadd"},
		{"pid": uint32(3), "comm": "ksoftirqd"},
	}

	err = structArrayField.PutStructArray(data, input)
	require.NoError(t, err)

	output, err := structArrayField.GetStructArray(data)
	require.NoError(t, err)

	require.Len(t, output, 3)
	for i, expected := range input {
		assert.Equal(t, expected["pid"], output[i]["pid"])
		assert.Equal(t, expected["comm"], output[i]["comm"])
	}
}

func TestStructFieldWrongKind(t *testing.T) {
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	// Create a non-struct field
	field, err := ds.AddField("notStruct", api.Kind_Uint32)
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// GetStruct should fail on non-struct field
	_, err = field.GetStruct(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a struct")

	// PutStruct should fail on non-struct field
	err = field.PutStruct(data, map[string]any{"foo": "bar"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a struct")
}

func TestStructFieldMissingDefinition(t *testing.T) {
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	// Create struct field WITHOUT annotation
	field, err := ds.AddField("noDefStruct", api.Kind_Kind_Struct,
		WithFlags(FieldFlagDynamicSize))
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	// GetStruct should fail without definition
	_, err = field.GetStruct(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no struct definition")
}

func TestStructFieldFormatColumn(t *testing.T) {
	// Create struct definition
	def := proto.NewStructDef("Info").
		AddField("a", api.Kind_Uint32).
		AddField("b", api.Kind_String)

	defSchema, err := def.SerializeSchema()
	require.NoError(t, err)

	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	field, err := ds.AddField("info", api.Kind_Kind_Struct,
		WithFlags(FieldFlagDynamicSize),
		WithAnnotation(AnnotationStructFields, defSchema))
	require.NoError(t, err)

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = field.PutStruct(data, map[string]any{
		"a": uint32(42),
		"b": "hello",
	})
	require.NoError(t, err)

	// StringForColumn should format the struct
	s := field.StringForColumn(data)
	assert.NotEmpty(t, s)
	assert.NotEqual(t, "{struct}", s)
}

func TestEncodeStructCallback(t *testing.T) {
	// Create struct definition
	def := proto.NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("comm", api.Kind_String)

	defSchema, err := def.SerializeSchema()
	require.NoError(t, err)

	// Create datasource with struct field
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	structField, err := ds.AddField("data", api.Kind_Kind_Struct,
		WithFlags(FieldFlagDynamicSize),
		WithAnnotation(AnnotationStructFields, defSchema))
	require.NoError(t, err)

	// Get the accessor for typed encoding
	accessor := structField.StructAccessor()
	require.NotNil(t, accessor)

	pidField := accessor.Field(0)
	commField := accessor.Field(1)
	require.NotNil(t, pidField)
	require.NotNil(t, commField)

	// Create data and encode using callback
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = structField.EncodeStruct(data, func(b *proto.StructBuilder) {
		pidField.PutUint32(b, 1234)
		commField.PutString(b, "test-process")
	})
	require.NoError(t, err)

	// Decode and verify
	output, err := structField.GetStruct(data)
	require.NoError(t, err)

	assert.Equal(t, uint32(1234), output["pid"])
	assert.Equal(t, "test-process", output["comm"])
}

func TestEncodeStructArrayCallback(t *testing.T) {
	// Create struct definition
	def := proto.NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	defSchema, err := def.SerializeSchema()
	require.NoError(t, err)

	// Create datasource with struct array field
	ds, err := New(TypeSingle, "test")
	require.NoError(t, err)

	arrayField, err := ds.AddField("items", api.Kind_Kind_StructArray,
		WithFlags(FieldFlagDynamicSize),
		WithAnnotation(AnnotationStructFields, defSchema))
	require.NoError(t, err)

	// Get the accessor for typed encoding
	accessor := arrayField.StructAccessor()
	require.NotNil(t, accessor)

	idField := accessor.Field(0)
	nameField := accessor.Field(1)

	// Create test data
	type item struct {
		id   uint32
		name string
	}
	items := []item{
		{1, "item1"},
		{2, "item2"},
		{3, "item3"},
	}

	// Create data and encode using callback
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)

	err = arrayField.EncodeStructArray(data, len(items), func(idx int, b *proto.StructBuilder) {
		idField.PutUint32(b, items[idx].id)
		nameField.PutString(b, items[idx].name)
	})
	require.NoError(t, err)

	// Decode and verify
	output, err := arrayField.GetStructArray(data)
	require.NoError(t, err)

	require.Len(t, output, 3)
	for i, item := range items {
		assert.Equal(t, item.id, output[i]["id"])
		assert.Equal(t, item.name, output[i]["name"])
	}
}
