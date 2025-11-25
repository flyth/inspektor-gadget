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
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestStructDefCreation(t *testing.T) {
	def := NewStructDef("TestStruct").
		AddField("pid", api.Kind_Uint32).
		AddField("comm", api.Kind_String).
		AddField("count", api.Kind_Int64)

	if def.Name != "TestStruct" {
		t.Errorf("Name = %q, want %q", def.Name, "TestStruct")
	}

	if len(def.Fields) != 3 {
		t.Fatalf("len(Fields) = %d, want 3", len(def.Fields))
	}

	// Check field numbers are assigned correctly (1-based)
	for i, f := range def.Fields {
		if f.FieldNum != i+1 {
			t.Errorf("Field %d: FieldNum = %d, want %d", i, f.FieldNum, i+1)
		}
	}

	// Check field by name lookup
	pidField := def.GetFieldByName("pid")
	if pidField == nil {
		t.Fatal("GetFieldByName(pid) returned nil")
	}
	if pidField.Kind != api.Kind_Uint32 {
		t.Errorf("pid.Kind = %v, want %v", pidField.Kind, api.Kind_Uint32)
	}

	// Check field by number lookup
	field2 := def.GetFieldByNum(2)
	if field2 == nil {
		t.Fatal("GetFieldByNum(2) returned nil")
	}
	if field2.Name != "comm" {
		t.Errorf("field2.Name = %q, want %q", field2.Name, "comm")
	}
}

func TestStructDefWithArrays(t *testing.T) {
	def := NewStructDef("ProcessInfo").
		AddField("pid", api.Kind_Uint32).
		AddArrayField("fds", api.Kind_Int32).
		AddField("comm", api.Kind_String)

	if len(def.Fields) != 3 {
		t.Fatalf("len(Fields) = %d, want 3", len(def.Fields))
	}

	fdsField := def.GetFieldByName("fds")
	if fdsField == nil {
		t.Fatal("GetFieldByName(fds) returned nil")
	}
	if !api.IsArrayKind(fdsField.Kind) {
		t.Errorf("fds.Kind should be an array kind")
	}
	if fdsField.ElemKind != api.Kind_Int32 {
		t.Errorf("fds.ElemKind = %v, want %v", fdsField.ElemKind, api.Kind_Int32)
	}
}

func TestStructDefWithNestedStruct(t *testing.T) {
	innerDef := NewStructDef("Inner").
		AddField("value", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	outerDef := NewStructDef("Outer").
		AddField("id", api.Kind_Uint64).
		AddNestedField("inner", innerDef)

	if len(outerDef.Fields) != 2 {
		t.Fatalf("len(Fields) = %d, want 2", len(outerDef.Fields))
	}

	innerField := outerDef.GetFieldByName("inner")
	if innerField == nil {
		t.Fatal("GetFieldByName(inner) returned nil")
	}
	if innerField.Kind != api.Kind_Kind_Struct {
		t.Errorf("inner.Kind = %v, want %v", innerField.Kind, api.Kind_Kind_Struct)
	}
	if innerField.NestedDef != innerDef {
		t.Error("inner.NestedDef should point to innerDef")
	}
}

func TestStructDefToProtoDescriptor(t *testing.T) {
	def := NewStructDef("TestMessage").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String).
		AddArrayField("tags", api.Kind_String)

	desc, err := def.ToProtoDescriptor()
	if err != nil {
		t.Fatalf("ToProtoDescriptor() error: %v", err)
	}

	if desc.Name() != "TestMessage" {
		t.Errorf("desc.Name() = %q, want %q", desc.Name(), "TestMessage")
	}

	if desc.Fields().Len() != 3 {
		t.Errorf("desc.Fields().Len() = %d, want 3", desc.Fields().Len())
	}
}

func TestStructEncoderScalarFields(t *testing.T) {
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

	encoded, err := enc.Encode(data)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("encoded data should not be empty")
	}
}

func TestStructEncoderArrayFields(t *testing.T) {
	def := NewStructDef("Stats").
		AddField("name", api.Kind_String).
		AddArrayField("values", api.Kind_Uint32)

	enc := NewStructEncoder(def, 256)
	data := map[string]any{
		"name":   "test",
		"values": []uint32{1, 2, 3, 4, 5},
	}

	encoded, err := enc.Encode(data)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("encoded data should not be empty")
	}
}

func TestStructEncoderNestedStruct(t *testing.T) {
	innerDef := NewStructDef("Inner").
		AddField("x", api.Kind_Int32).
		AddField("y", api.Kind_Int32)

	outerDef := NewStructDef("Outer").
		AddField("id", api.Kind_Uint64).
		AddNestedField("point", innerDef)

	enc := NewStructEncoder(outerDef, 256)
	data := map[string]any{
		"id": uint64(42),
		"point": map[string]any{
			"x": int32(10),
			"y": int32(20),
		},
	}

	encoded, err := enc.Encode(data)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	if len(encoded) == 0 {
		t.Fatal("encoded data should not be empty")
	}
}

func TestStructEncoderMissingFields(t *testing.T) {
	def := NewStructDef("Test").
		AddField("required", api.Kind_String).
		AddField("optional", api.Kind_Uint32)

	enc := NewStructEncoder(def, 256)
	data := map[string]any{
		"required": "hello",
		// optional is missing
	}

	encoded, err := enc.Encode(data)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Should succeed with missing optional field
	if len(encoded) == 0 {
		t.Fatal("encoded data should not be empty")
	}
}

func TestStructDecoderScalarFields(t *testing.T) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("comm", api.Kind_String)

	// Create decoder first to validate it works
	dec, err := NewStructDecoder(def)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	// Encode test data
	enc := NewStructEncoder(def, 256)
	original := map[string]any{
		"pid":  uint32(1234),
		"ppid": uint32(1),
		"comm": "bash",
	}

	encoded, err := enc.Encode(original)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify
	if decoded["pid"] != original["pid"] {
		t.Errorf("pid = %v, want %v", decoded["pid"], original["pid"])
	}
	if decoded["ppid"] != original["ppid"] {
		t.Errorf("ppid = %v, want %v", decoded["ppid"], original["ppid"])
	}
	if decoded["comm"] != original["comm"] {
		t.Errorf("comm = %v, want %v", decoded["comm"], original["comm"])
	}
}

func TestStructRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		def  *StructDef
		data map[string]any
	}{
		{
			name: "scalar fields",
			def: NewStructDef("Test1").
				AddField("u32", api.Kind_Uint32).
				AddField("i64", api.Kind_Int64).
				AddField("str", api.Kind_String),
			data: map[string]any{
				"u32": uint32(42),
				"i64": int64(-100),
				"str": "hello",
			},
		},
		{
			name: "array fields",
			def: NewStructDef("Test2").
				AddField("name", api.Kind_String).
				AddArrayField("ids", api.Kind_Uint32),
			data: map[string]any{
				"name": "test",
				"ids":  []uint32{1, 2, 3, 4, 5},
			},
		},
		{
			name: "float fields",
			def: NewStructDef("Test3").
				AddField("f32", api.Kind_Float32).
				AddField("f64", api.Kind_Float64),
			data: map[string]any{
				"f32": float32(1.5),
				"f64": float64(2.5),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewStructEncoder(tt.def, 256)
			dec, err := NewStructDecoder(tt.def)
			if err != nil {
				t.Fatalf("NewStructDecoder() error: %v", err)
			}

			// Encode
			encoded, err := enc.Encode(tt.data)
			if err != nil {
				t.Fatalf("Encode() error: %v", err)
			}

			// Decode
			decoded, err := dec.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode() error: %v", err)
			}

			// Compare
			if !reflect.DeepEqual(decoded, tt.data) {
				t.Errorf("Round trip failed:\n  original: %v\n  decoded:  %v", tt.data, decoded)
			}
		})
	}
}

func TestStructArrayRoundTrip(t *testing.T) {
	itemDef := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	enc := NewStructEncoder(itemDef, 256)
	dec, err := NewStructDecoder(itemDef)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	items := []map[string]any{
		{"id": uint32(1), "name": "item1"},
		{"id": uint32(2), "name": "item2"},
		{"id": uint32(3), "name": "item3"},
	}

	// Encode as struct array
	encoded, err := enc.EncodeStructArray(1, items)
	if err != nil {
		t.Fatalf("EncodeStructArray() error: %v", err)
	}

	// Decode
	decoded, err := dec.DecodeStructArray(encoded)
	if err != nil {
		t.Fatalf("DecodeStructArray() error: %v", err)
	}

	// Compare
	if len(decoded) != len(items) {
		t.Fatalf("len(decoded) = %d, want %d", len(decoded), len(items))
	}

	for i := range items {
		if !reflect.DeepEqual(decoded[i], items[i]) {
			t.Errorf("item %d: got %v, want %v", i, decoded[i], items[i])
		}
	}
}

func TestNestedStructRoundTrip(t *testing.T) {
	innerDef := NewStructDef("Inner").
		AddField("x", api.Kind_Int32).
		AddField("y", api.Kind_Int32)

	outerDef := NewStructDef("Outer").
		AddField("id", api.Kind_Uint64).
		AddNestedField("point", innerDef)

	enc := NewStructEncoder(outerDef, 256)
	dec, err := NewStructDecoder(outerDef)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	original := map[string]any{
		"id": uint64(42),
		"point": map[string]any{
			"x": int32(10),
			"y": int32(20),
		},
	}

	// Encode
	encoded, err := enc.Encode(original)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify nested struct
	if decoded["id"] != original["id"] {
		t.Errorf("id = %v, want %v", decoded["id"], original["id"])
	}

	decodedPoint, ok := decoded["point"].(map[string]any)
	if !ok {
		t.Fatalf("point is not map[string]any, got %T", decoded["point"])
	}
	originalPoint := original["point"].(map[string]any)

	if decodedPoint["x"] != originalPoint["x"] {
		t.Errorf("point.x = %v, want %v", decodedPoint["x"], originalPoint["x"])
	}
	if decodedPoint["y"] != originalPoint["y"] {
		t.Errorf("point.y = %v, want %v", decodedPoint["y"], originalPoint["y"])
	}
}

func TestStructArrayOfStructsRoundTrip(t *testing.T) {
	eventDef := NewStructDef("Event").
		AddField("type", api.Kind_Uint32).
		AddField("data", api.Kind_String)

	containerDef := NewStructDef("Container").
		AddField("name", api.Kind_String).
		AddNestedArrayField("events", eventDef)

	enc := NewStructEncoder(containerDef, 512)
	dec, err := NewStructDecoder(containerDef)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	original := map[string]any{
		"name": "mycontainer",
		"events": []map[string]any{
			{"type": uint32(1), "data": "event1"},
			{"type": uint32(2), "data": "event2"},
		},
	}

	// Encode
	encoded, err := enc.Encode(original)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify
	if decoded["name"] != original["name"] {
		t.Errorf("name = %v, want %v", decoded["name"], original["name"])
	}

	decodedEvents, ok := decoded["events"].([]map[string]any)
	if !ok {
		t.Fatalf("events is not []map[string]any, got %T", decoded["events"])
	}
	originalEvents := original["events"].([]map[string]any)

	if len(decodedEvents) != len(originalEvents) {
		t.Fatalf("len(events) = %d, want %d", len(decodedEvents), len(originalEvents))
	}

	for i := range originalEvents {
		if !reflect.DeepEqual(decodedEvents[i], originalEvents[i]) {
			t.Errorf("events[%d] = %v, want %v", i, decodedEvents[i], originalEvents[i])
		}
	}
}

func TestComplexNestedStructure(t *testing.T) {
	// Build a complex structure: Process with nested arrays and structs
	fileDef := NewStructDef("File").
		AddField("fd", api.Kind_Int32).
		AddField("path", api.Kind_String)

	processDef := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("comm", api.Kind_String).
		AddArrayField("envp", api.Kind_String).
		AddNestedArrayField("files", fileDef)

	enc := NewStructEncoder(processDef, 1024)
	dec, err := NewStructDecoder(processDef)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	original := map[string]any{
		"pid":  uint32(12345),
		"comm": "myproc",
		"envp": []string{"HOME=/root", "PATH=/usr/bin", "USER=root"},
		"files": []map[string]any{
			{"fd": int32(0), "path": "/dev/stdin"},
			{"fd": int32(1), "path": "/dev/stdout"},
			{"fd": int32(2), "path": "/dev/stderr"},
		},
	}

	// Encode
	encoded, err := enc.Encode(original)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	// Decode
	decoded, err := dec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	// Verify scalar fields
	if decoded["pid"] != original["pid"] {
		t.Errorf("pid = %v, want %v", decoded["pid"], original["pid"])
	}
	if decoded["comm"] != original["comm"] {
		t.Errorf("comm = %v, want %v", decoded["comm"], original["comm"])
	}

	// Verify string array
	decodedEnvp, ok := decoded["envp"].([]string)
	if !ok {
		t.Fatalf("envp is not []string, got %T", decoded["envp"])
	}
	originalEnvp := original["envp"].([]string)
	if !reflect.DeepEqual(decodedEnvp, originalEnvp) {
		t.Errorf("envp = %v, want %v", decodedEnvp, originalEnvp)
	}

	// Verify struct array
	decodedFiles, ok := decoded["files"].([]map[string]any)
	if !ok {
		t.Fatalf("files is not []map[string]any, got %T", decoded["files"])
	}
	originalFiles := original["files"].([]map[string]any)
	if len(decodedFiles) != len(originalFiles) {
		t.Fatalf("len(files) = %d, want %d", len(decodedFiles), len(originalFiles))
	}
	for i := range originalFiles {
		if !reflect.DeepEqual(decodedFiles[i], originalFiles[i]) {
			t.Errorf("files[%d] = %v, want %v", i, decodedFiles[i], originalFiles[i])
		}
	}
}

func TestDecodeEmptyStruct(t *testing.T) {
	def := NewStructDef("Empty").
		AddField("id", api.Kind_Uint32)

	dec, err := NewStructDecoder(def)
	if err != nil {
		t.Fatalf("NewStructDecoder() error: %v", err)
	}

	// Decode empty bytes
	decoded, err := dec.Decode([]byte{})
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("decoded should be empty, got %v", decoded)
	}
}

// Benchmark tests

func BenchmarkStructEncode_Simple(b *testing.B) {
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

func BenchmarkStructDecode_Simple(b *testing.B) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("uid", api.Kind_Uint64).
		AddField("comm", api.Kind_String)

	enc := NewStructEncoder(def, 256)
	dec, _ := NewStructDecoder(def)

	data := map[string]any{
		"pid":  uint32(1234),
		"ppid": uint32(1),
		"uid":  uint64(1000),
		"comm": "bash",
	}
	encoded, _ := enc.Encode(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dec.Decode(encoded)
	}
}

func BenchmarkStructRoundTrip_Simple(b *testing.B) {
	def := NewStructDef("Process").
		AddField("pid", api.Kind_Uint32).
		AddField("ppid", api.Kind_Uint32).
		AddField("uid", api.Kind_Uint64).
		AddField("comm", api.Kind_String)

	enc := NewStructEncoder(def, 256)
	dec, _ := NewStructDecoder(def)

	data := map[string]any{
		"pid":  uint32(1234),
		"ppid": uint32(1),
		"uid":  uint64(1000),
		"comm": "bash",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := enc.Encode(data)
		_, _ = dec.Decode(encoded)
	}
}

func BenchmarkStructEncode_10Fields(b *testing.B) {
	def := NewStructDef("TenFields")
	for i := 0; i < 10; i++ {
		def.AddField("field"+string(rune('a'+i)), api.Kind_Uint32)
	}

	enc := NewStructEncoder(def, 256)
	data := make(map[string]any)
	for i := 0; i < 10; i++ {
		data["field"+string(rune('a'+i))] = uint32(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encode(data)
	}
}

func BenchmarkStructRoundTrip_10Fields(b *testing.B) {
	def := NewStructDef("TenFields")
	for i := 0; i < 10; i++ {
		def.AddField("field"+string(rune('a'+i)), api.Kind_Uint32)
	}

	enc := NewStructEncoder(def, 256)
	dec, _ := NewStructDecoder(def)

	data := make(map[string]any)
	for i := 0; i < 10; i++ {
		data["field"+string(rune('a'+i))] = uint32(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := enc.Encode(data)
		_, _ = dec.Decode(encoded)
	}
}

func BenchmarkStructArrayEncode_10Structs(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	enc := NewStructEncoder(def, 512)
	items := make([]map[string]any, 10)
	for i := 0; i < 10; i++ {
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

func BenchmarkStructArrayRoundTrip_10Structs(b *testing.B) {
	def := NewStructDef("Item").
		AddField("id", api.Kind_Uint32).
		AddField("name", api.Kind_String)

	enc := NewStructEncoder(def, 512)
	dec, _ := NewStructDecoder(def)

	items := make([]map[string]any, 10)
	for i := 0; i < 10; i++ {
		items[i] = map[string]any{
			"id":   uint32(i),
			"name": "item",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := enc.EncodeStructArray(1, items)
		_, _ = dec.DecodeStructArray(encoded)
	}
}
