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
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestStructAccessorBasic(t *testing.T) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("comm", api.Kind_String)

	accessor, err := NewStructAccessor(def)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	if accessor.NumFields() != 3 {
		t.Errorf("NumFields() = %d, want 3", accessor.NumFields())
	}

	// Get fields by index
	pidField := accessor.Field(0)
	ppidField := accessor.Field(1)
	commField := accessor.Field(2)

	if pidField == nil || ppidField == nil || commField == nil {
		t.Fatal("Field() returned nil")
	}

	// Encode using callback
	encoded := accessor.EncodeCallback(func(b *StructBuilder) {
		pidField.PutUint32(b, 1234)
		ppidField.PutUint32(b, 1)
		commField.PutString(b, "bash")
	})

	if len(encoded) == 0 {
		t.Fatal("encoded data is empty")
	}

	// Decode and verify
	decoded, err := accessor.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if decoded["pid"] != uint32(1234) {
		t.Errorf("pid = %v, want 1234", decoded["pid"])
	}
	if decoded["ppid"] != uint32(1) {
		t.Errorf("ppid = %v, want 1", decoded["ppid"])
	}
	if decoded["comm"] != "bash" {
		t.Errorf("comm = %v, want bash", decoded["comm"])
	}
}

func TestStructAccessorByName(t *testing.T) {
	def := NewStructDef("Test").
		AddField("a", api.Kind_Uint32).
		AddField("b", api.Kind_String)

	accessor, err := NewStructAccessor(def)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	aField := accessor.FieldByName("a")
	bField := accessor.FieldByName("b")

	if aField == nil || bField == nil {
		t.Fatal("FieldByName() returned nil")
	}

	if aField.FieldNum() != 1 {
		t.Errorf("aField.FieldNum() = %d, want 1", aField.FieldNum())
	}
	if bField.FieldNum() != 2 {
		t.Errorf("bField.FieldNum() = %d, want 2", bField.FieldNum())
	}
}

func TestStructAccessorArray(t *testing.T) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	accessor, err := NewStructAccessor(def)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	idField := accessor.Field(0)
	nameField := accessor.Field(1)

	items := []struct {
		id   uint32
		name string
	}{
		{1, "item1"},
		{2, "item2"},
		{3, "item3"},
	}

	encoded := accessor.EncodeStructArrayCallback(1, len(items), func(idx int, b *StructBuilder) {
		idField.PutUint32(b, items[idx].id)
		nameField.PutString(b, items[idx].name)
	})

	if len(encoded) == 0 {
		t.Fatal("encoded data is empty")
	}

	// Decode and verify
	decoded, err := accessor.DecodeStructArray(encoded)
	if err != nil {
		t.Fatalf("DecodeStructArray() error: %v", err)
	}

	if len(decoded) != 3 {
		t.Fatalf("len(decoded) = %d, want 3", len(decoded))
	}

	for i, item := range items {
		if decoded[i]["id"] != item.id {
			t.Errorf("decoded[%d][id] = %v, want %v", i, decoded[i]["id"], item.id)
		}
		if decoded[i]["name"] != item.name {
			t.Errorf("decoded[%d][name] = %v, want %v", i, decoded[i]["name"], item.name)
		}
	}
}

func TestStructAccessorNestedStruct(t *testing.T) {
	innerDef := NewStructDef("Inner").
		AddField("x", api.Kind_Int32).
		AddField("y", api.Kind_Int32)

	outerDef := NewStructDef("Outer").
		AddField("id", api.Kind_Uint64).
		AddNestedField("point", innerDef)

	accessor, err := NewStructAccessor(outerDef)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	idField := accessor.Field(0)
	pointField := accessor.Field(1)

	if pointField.nested == nil {
		t.Fatal("nested accessor is nil")
	}

	xField := pointField.nested.Field(0)
	yField := pointField.nested.Field(1)

	encoded := accessor.EncodeCallback(func(b *StructBuilder) {
		idField.PutUint64(b, 42)
		pointField.PutNested(b, func(nb *StructBuilder) {
			xField.PutInt32(nb, 10)
			yField.PutInt32(nb, 20)
		})
	})

	if len(encoded) == 0 {
		t.Fatal("encoded data is empty")
	}

	// Decode and verify
	decoded, err := accessor.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if decoded["id"] != uint64(42) {
		t.Errorf("id = %v, want 42", decoded["id"])
	}

	point, ok := decoded["point"].(map[string]any)
	if !ok {
		t.Fatalf("point is not map[string]any, got %T", decoded["point"])
	}
	if point["x"] != int32(10) {
		t.Errorf("point.x = %v, want 10", point["x"])
	}
	if point["y"] != int32(20) {
		t.Errorf("point.y = %v, want 20", point["y"])
	}
}

func TestStructAccessorArrayFields(t *testing.T) {
	def := NewStructDef("Data").
		AddField("name", api.Kind_String).
		AddArrayField("values", api.Kind_Uint32).
		AddArrayField("tags", api.Kind_String)

	accessor, err := NewStructAccessor(def)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	nameField := accessor.Field(0)
	valuesField := accessor.Field(1)
	tagsField := accessor.Field(2)

	encoded := accessor.EncodeCallback(func(b *StructBuilder) {
		nameField.PutString(b, "test")
		valuesField.PutUint32Array(b, []uint32{1, 2, 3, 4, 5})
		tagsField.PutStringArray(b, []string{"a", "b", "c"})
	})

	decoded, err := accessor.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if decoded["name"] != "test" {
		t.Errorf("name = %v, want test", decoded["name"])
	}

	values, ok := decoded["values"].([]uint32)
	if !ok {
		t.Fatalf("values is not []uint32, got %T", decoded["values"])
	}
	if len(values) != 5 {
		t.Errorf("len(values) = %d, want 5", len(values))
	}

	tags, ok := decoded["tags"].([]string)
	if !ok {
		t.Fatalf("tags is not []string, got %T", decoded["tags"])
	}
	if len(tags) != 3 {
		t.Errorf("len(tags) = %d, want 3", len(tags))
	}
}

func TestStructBuilderReset(t *testing.T) {
	def := NewStructDef("Test").
		AddField("x", api.Kind_Uint32)

	accessor, err := NewStructAccessor(def)
	if err != nil {
		t.Fatalf("NewStructAccessor() error: %v", err)
	}

	xField := accessor.Field(0)

	// Encode multiple times to test reuse
	for i := 0; i < 100; i++ {
		encoded := accessor.EncodeCallback(func(b *StructBuilder) {
			xField.PutUint32(b, uint32(i))
		})

		decoded, err := accessor.Decode(encoded)
		if err != nil {
			t.Fatalf("iteration %d: Decode() error: %v", i, err)
		}
		if decoded["x"] != uint32(i) {
			t.Errorf("iteration %d: x = %v, want %v", i, decoded["x"], i)
		}
	}
}

// Benchmarks

func BenchmarkStructAccessor_Encode(b *testing.B) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("uid", api.Kind_Uint64).
		AddField("comm", api.Kind_String)

	accessor, _ := NewStructAccessor(def)
	pidField := accessor.Field(0)
	ppidField := accessor.Field(1)
	uidField := accessor.Field(2)
	commField := accessor.Field(3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accessor.EncodeCallback(func(b *StructBuilder) {
			pidField.PutUint32(b, 1234)
			ppidField.PutUint32(b, 1)
			uidField.PutUint64(b, 1000)
			commField.PutString(b, "bash")
		})
	}
}

func BenchmarkStructEncoder_Encode(b *testing.B) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("uid", api.Kind_Uint64).
		AddField("comm", api.Kind_String)

	enc := NewStructEncoder(def, 256)
	data := map[string]any{
		"pid":  uint32(1234),
		"ppid": uint32(1),
		"uid":  uint64(1000),
		"comm": "bash",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encode(data)
	}
}

func BenchmarkStructAccessor_EncodeArray10(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	accessor, _ := NewStructAccessor(def)
	idField := accessor.Field(0)
	nameField := accessor.Field(1)

	type item struct {
		id   uint32
		name string
	}
	items := make([]item, 10)
	for i := range items {
		items[i] = item{id: uint32(i), name: "item"}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accessor.EncodeStructArrayCallback(1, len(items), func(idx int, b *StructBuilder) {
			idField.PutUint32(b, items[idx].id)
			nameField.PutString(b, items[idx].name)
		})
	}
}

func BenchmarkStructEncoder_EncodeArray10(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	enc := NewStructEncoder(def, 512)

	items := make([]map[string]any, 10)
	for i := range items {
		items[i] = map[string]any{
			"id":   uint32(i),
			"name": "item",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.EncodeStructArray(1, items)
	}
}

func BenchmarkStructAccessor_EncodeArray100(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	accessor, _ := NewStructAccessor(def)
	idField := accessor.Field(0)
	nameField := accessor.Field(1)

	type item struct {
		id   uint32
		name string
	}
	items := make([]item, 100)
	for i := range items {
		items[i] = item{id: uint32(i), name: "item"}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = accessor.EncodeStructArrayCallback(1, len(items), func(idx int, b *StructBuilder) {
			idField.PutUint32(b, items[idx].id)
			nameField.PutString(b, items[idx].name)
		})
	}
}

func BenchmarkStructEncoder_EncodeArray100(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	enc := NewStructEncoder(def, 4096)

	items := make([]map[string]any, 100)
	for i := range items {
		items[i] = map[string]any{
			"id":   uint32(i),
			"name": "item",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.EncodeStructArray(1, items)
	}
}
