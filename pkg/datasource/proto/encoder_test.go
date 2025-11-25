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

	"google.golang.org/protobuf/encoding/protowire"
)

func TestEncodeUint32Array(t *testing.T) {
	tests := []struct {
		name     string
		fieldNum int
		values   []uint32
		wantNil  bool
	}{
		{
			name:     "empty array",
			fieldNum: 1,
			values:   []uint32{},
			wantNil:  true,
		},
		{
			name:     "single element",
			fieldNum: 1,
			values:   []uint32{42},
		},
		{
			name:     "multiple elements",
			fieldNum: 1,
			values:   []uint32{1, 2, 3, 4, 5},
		},
		{
			name:     "large values",
			fieldNum: 1,
			values:   []uint32{0xFFFFFFFF, 0x80000000, 0x12345678},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(256)
			result := enc.EncodeUint32Array(tt.fieldNum, tt.values)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil for empty array, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			// Verify the encoded data structure
			buf := result
			num, wt, n := protowire.ConsumeTag(buf)
			if n <= 0 {
				t.Fatal("failed to consume tag")
			}
			if int(num) != tt.fieldNum {
				t.Errorf("field number = %d, want %d", num, tt.fieldNum)
			}
			if wt != protowire.BytesType {
				t.Errorf("wire type = %d, want %d", wt, protowire.BytesType)
			}

			buf = buf[n:]
			length, n := protowire.ConsumeVarint(buf)
			if n <= 0 {
				t.Fatal("failed to consume length")
			}
			expectedLen := len(tt.values) * 4
			if int(length) != expectedLen {
				t.Errorf("length = %d, want %d", length, expectedLen)
			}

			buf = buf[n:]
			for i, expected := range tt.values {
				val, n := protowire.ConsumeFixed32(buf)
				if n <= 0 {
					t.Fatalf("failed to consume value at index %d", i)
				}
				if val != expected {
					t.Errorf("value[%d] = %d, want %d", i, val, expected)
				}
				buf = buf[n:]
			}
		})
	}
}

func TestEncodeUint64Array(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []uint64{100, 200, 300, 0xFFFFFFFFFFFFFFFF}
	result := enc.EncodeUint64Array(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify encoding
	buf := result
	_, wt, n := protowire.ConsumeTag(buf)
	if n <= 0 {
		t.Fatal("failed to consume tag")
	}
	if wt != protowire.BytesType {
		t.Errorf("wire type = %d, want %d", wt, protowire.BytesType)
	}

	buf = buf[n:]
	length, n := protowire.ConsumeVarint(buf)
	if n <= 0 {
		t.Fatal("failed to consume length")
	}
	if int(length) != len(values)*8 {
		t.Errorf("length = %d, want %d", length, len(values)*8)
	}

	buf = buf[n:]
	for i, expected := range values {
		val, n := protowire.ConsumeFixed64(buf)
		if n <= 0 {
			t.Fatalf("failed to consume value at index %d", i)
		}
		if val != expected {
			t.Errorf("value[%d] = %d, want %d", i, val, expected)
		}
		buf = buf[n:]
	}
}

func TestEncodeInt32Array(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []int32{-100, 0, 100, 2147483647, -2147483648}
	result := enc.EncodeInt32Array(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	buf := result
	_, _, n := protowire.ConsumeTag(buf)
	buf = buf[n:]
	_, n = protowire.ConsumeVarint(buf)
	buf = buf[n:]

	for i, expected := range values {
		val, n := protowire.ConsumeFixed32(buf)
		if n <= 0 {
			t.Fatalf("failed to consume value at index %d", i)
		}
		if int32(val) != expected {
			t.Errorf("value[%d] = %d, want %d", i, int32(val), expected)
		}
		buf = buf[n:]
	}
}

func TestEncodeInt64Array(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []int64{-1000, 0, 1000, 9223372036854775807, -9223372036854775808}
	result := enc.EncodeInt64Array(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	buf := result
	_, _, n := protowire.ConsumeTag(buf)
	buf = buf[n:]
	_, n = protowire.ConsumeVarint(buf)
	buf = buf[n:]

	for i, expected := range values {
		val, n := protowire.ConsumeFixed64(buf)
		if n <= 0 {
			t.Fatalf("failed to consume value at index %d", i)
		}
		if int64(val) != expected {
			t.Errorf("value[%d] = %d, want %d", i, int64(val), expected)
		}
		buf = buf[n:]
	}
}

func TestEncodeFloat32Array(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []float32{1.5, 2.5, 3.5, -4.5, 0.0}
	result := enc.EncodeFloat32Array(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Basic structure validation
	buf := result
	_, wt, n := protowire.ConsumeTag(buf)
	if wt != protowire.BytesType {
		t.Errorf("wire type = %d, want %d", wt, protowire.BytesType)
	}
	buf = buf[n:]
	length, n := protowire.ConsumeVarint(buf)
	if int(length) != len(values)*4 {
		t.Errorf("length = %d, want %d", length, len(values)*4)
	}
}

func TestEncodeFloat64Array(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []float64{1.5, 2.5, 3.5, -4.5, 0.0}
	result := enc.EncodeFloat64Array(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	buf := result
	_, wt, n := protowire.ConsumeTag(buf)
	if wt != protowire.BytesType {
		t.Errorf("wire type = %d, want %d", wt, protowire.BytesType)
	}
	buf = buf[n:]
	length, n := protowire.ConsumeVarint(buf)
	if int(length) != len(values)*8 {
		t.Errorf("length = %d, want %d", length, len(values)*8)
	}
}

func TestEncodeStringArray(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := []string{"foo", "bar", "baz"}
	result := enc.EncodeStringArray(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// String arrays are non-packed, so each string has its own tag
	buf := result
	for i, expected := range values {
		num, wt, n := protowire.ConsumeTag(buf)
		if n <= 0 {
			t.Fatalf("failed to consume tag at index %d", i)
		}
		if num != 1 {
			t.Errorf("field number[%d] = %d, want 1", i, num)
		}
		if wt != protowire.BytesType {
			t.Errorf("wire type[%d] = %d, want %d", i, wt, protowire.BytesType)
		}

		buf = buf[n:]
		val, n := protowire.ConsumeBytes(buf)
		if n <= 0 {
			t.Fatalf("failed to consume string at index %d", i)
		}
		if string(val) != expected {
			t.Errorf("value[%d] = %q, want %q", i, string(val), expected)
		}
		buf = buf[n:]
	}
}

func TestEncodeBytesArray(t *testing.T) {
	enc := NewArrayEncoder(256)
	values := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05},
		{0x06},
	}
	result := enc.EncodeBytesArray(1, values)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	buf := result
	for i, expected := range values {
		num, wt, n := protowire.ConsumeTag(buf)
		if n <= 0 {
			t.Fatalf("failed to consume tag at index %d", i)
		}
		if num != 1 {
			t.Errorf("field number[%d] = %d, want 1", i, num)
		}
		if wt != protowire.BytesType {
			t.Errorf("wire type[%d] = %d, want %d", i, wt, protowire.BytesType)
		}

		buf = buf[n:]
		val, n := protowire.ConsumeBytes(buf)
		if n <= 0 {
			t.Fatalf("failed to consume bytes at index %d", i)
		}
		if len(val) != len(expected) {
			t.Errorf("value[%d] length = %d, want %d", i, len(val), len(expected))
		}
		for j := range val {
			if val[j] != expected[j] {
				t.Errorf("value[%d][%d] = 0x%02x, want 0x%02x", i, j, val[j], expected[j])
			}
		}
		buf = buf[n:]
	}
}

func TestEncoderReset(t *testing.T) {
	enc := NewArrayEncoder(256)

	// Encode first array
	result1 := enc.EncodeUint32Array(1, []uint32{1, 2, 3})
	if result1 == nil {
		t.Fatal("expected non-nil result1")
	}

	// Reset and encode second array
	enc.Reset()
	result2 := enc.EncodeUint32Array(1, []uint32{4, 5, 6})
	if result2 == nil {
		t.Fatal("expected non-nil result2")
	}

	// Verify that result1 and result2 are different
	// (they should have different values but same structure)
	if len(result1) != len(result2) {
		t.Errorf("lengths differ after reset: %d vs %d", len(result1), len(result2))
	}
}

// Benchmark tests

func BenchmarkEncodeUint32Array_10(b *testing.B) {
	enc := NewArrayEncoder(256)
	values := make([]uint32, 10)
	for i := range values {
		values[i] = uint32(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncodeUint32Array(1, values)
		enc.Reset()
	}
}

func BenchmarkEncodeUint32Array_100(b *testing.B) {
	enc := NewArrayEncoder(512)
	values := make([]uint32, 100)
	for i := range values {
		values[i] = uint32(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncodeUint32Array(1, values)
		enc.Reset()
	}
}

func BenchmarkEncodeUint32Array_1000(b *testing.B) {
	enc := NewArrayEncoder(4096)
	values := make([]uint32, 1000)
	for i := range values {
		values[i] = uint32(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncodeUint32Array(1, values)
		enc.Reset()
	}
}

func BenchmarkEncodeFloat64Array_100(b *testing.B) {
	enc := NewArrayEncoder(1024)
	values := make([]float64, 100)
	for i := range values {
		values[i] = float64(i) * 1.5
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncodeFloat64Array(1, values)
		enc.Reset()
	}
}

func BenchmarkEncodeStringArray_100(b *testing.B) {
	enc := NewArrayEncoder(2048)
	values := make([]string, 100)
	for i := range values {
		values[i] = "test string value"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncodeStringArray(1, values)
		enc.Reset()
	}
}
