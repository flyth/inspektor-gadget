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
	"math"
	"reflect"
	"testing"
)

func TestDecodeUint32Array(t *testing.T) {
	tests := []struct {
		name    string
		input   []uint32
		wantErr bool
	}{
		{
			name:  "single element",
			input: []uint32{42},
		},
		{
			name:  "multiple elements",
			input: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:  "large values",
			input: []uint32{0xFFFFFFFF, 0x80000000, 0x12345678},
		},
		{
			name:  "100 elements",
			input: makeUint32Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(1024)
			encoded := enc.EncodeUint32Array(1, tt.input)

			result, err := DecodeUint32Array(encoded)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeUint32Array() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeUint32Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeUint64Array(t *testing.T) {
	tests := []struct {
		name  string
		input []uint64
	}{
		{
			name:  "small values",
			input: []uint64{100, 200, 300},
		},
		{
			name:  "large values",
			input: []uint64{0xFFFFFFFFFFFFFFFF, 0x8000000000000000, 0x123456789ABCDEF0},
		},
		{
			name:  "100 elements",
			input: makeUint64Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(2048)
			encoded := enc.EncodeUint64Array(1, tt.input)

			result, err := DecodeUint64Array(encoded)

			if err != nil {
				t.Errorf("DecodeUint64Array() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeUint64Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeInt32Array(t *testing.T) {
	tests := []struct {
		name  string
		input []int32
	}{
		{
			name:  "positive and negative",
			input: []int32{-100, 0, 100},
		},
		{
			name:  "extreme values",
			input: []int32{math.MaxInt32, math.MinInt32, 0, 1, -1},
		},
		{
			name:  "100 elements",
			input: makeInt32Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(1024)
			encoded := enc.EncodeInt32Array(1, tt.input)

			result, err := DecodeInt32Array(encoded)

			if err != nil {
				t.Errorf("DecodeInt32Array() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeInt32Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeInt64Array(t *testing.T) {
	tests := []struct {
		name  string
		input []int64
	}{
		{
			name:  "positive and negative",
			input: []int64{-1000, 0, 1000},
		},
		{
			name:  "extreme values",
			input: []int64{math.MaxInt64, math.MinInt64, 0, 1, -1},
		},
		{
			name:  "100 elements",
			input: makeInt64Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(2048)
			encoded := enc.EncodeInt64Array(1, tt.input)

			result, err := DecodeInt64Array(encoded)

			if err != nil {
				t.Errorf("DecodeInt64Array() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeInt64Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeFloat32Array(t *testing.T) {
	tests := []struct {
		name  string
		input []float32
	}{
		{
			name:  "simple values",
			input: []float32{1.5, 2.5, 3.5, -4.5, 0.0},
		},
		{
			name:  "special values",
			input: []float32{0.0, -0.0, math.MaxFloat32, -math.MaxFloat32},
		},
		{
			name:  "100 elements",
			input: makeFloat32Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(1024)
			encoded := enc.EncodeFloat32Array(1, tt.input)

			result, err := DecodeFloat32Array(encoded)

			if err != nil {
				t.Errorf("DecodeFloat32Array() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeFloat32Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeFloat64Array(t *testing.T) {
	tests := []struct {
		name  string
		input []float64
	}{
		{
			name:  "simple values",
			input: []float64{1.5, 2.5, 3.5, -4.5, 0.0},
		},
		{
			name:  "special values",
			input: []float64{0.0, -0.0, math.MaxFloat64, -math.MaxFloat64},
		},
		{
			name:  "100 elements",
			input: makeFloat64Array(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(2048)
			encoded := enc.EncodeFloat64Array(1, tt.input)

			result, err := DecodeFloat64Array(encoded)

			if err != nil {
				t.Errorf("DecodeFloat64Array() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeFloat64Array() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeStringArray(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{
			name:  "simple strings",
			input: []string{"foo", "bar", "baz"},
		},
		{
			name:  "empty strings",
			input: []string{"", "a", "", "b"},
		},
		{
			name:  "unicode strings",
			input: []string{"hello", "世界", "🌍"},
		},
		{
			name:  "100 elements",
			input: makeStringArray(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(2048)
			encoded := enc.EncodeStringArray(1, tt.input)

			result, err := DecodeStringArray(encoded)

			if err != nil {
				t.Errorf("DecodeStringArray() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeStringArray() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeBytesArray(t *testing.T) {
	tests := []struct {
		name  string
		input [][]byte
	}{
		{
			name: "simple byte slices",
			input: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05},
				{0x06},
			},
		},
		{
			name: "empty slices",
			input: [][]byte{
				{},
				{0x01},
				{},
			},
		},
		{
			name:  "100 elements",
			input: makeBytesArray(100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewArrayEncoder(2048)
			encoded := enc.EncodeBytesArray(1, tt.input)

			result, err := DecodeBytesArray(encoded)

			if err != nil {
				t.Errorf("DecodeBytesArray() error = %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("DecodeBytesArray() = %v, want %v", result, tt.input)
			}
		})
	}
}

func TestDecodeEmptyData(t *testing.T) {
	// Empty input returns empty slice (consistent with encoder behavior)
	result32, err := DecodeUint32Array(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result32) != 0 {
		t.Errorf("expected empty slice, got %v", result32)
	}

	result64, err := DecodeUint64Array([]byte{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(result64) != 0 {
		t.Errorf("expected empty slice, got %v", result64)
	}

	resultStr, err := DecodeStringArray(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(resultStr) != 0 {
		t.Errorf("expected empty slice, got %v", resultStr)
	}
}

func TestDecodeInvalidData(t *testing.T) {
	// Invalid wire format
	_, err := DecodeUint32Array([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error for invalid data")
	}

	// Truncated data
	enc := NewArrayEncoder(256)
	encoded := enc.EncodeUint32Array(1, []uint32{1, 2, 3})
	truncated := encoded[:len(encoded)-1]

	_, err = DecodeUint32Array(truncated)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

// Helper functions to generate test data

func makeUint32Array(n int) []uint32 {
	result := make([]uint32, n)
	for i := 0; i < n; i++ {
		result[i] = uint32(i)
	}
	return result
}

func makeUint64Array(n int) []uint64 {
	result := make([]uint64, n)
	for i := 0; i < n; i++ {
		result[i] = uint64(i * 1000)
	}
	return result
}

func makeInt32Array(n int) []int32 {
	result := make([]int32, n)
	for i := 0; i < n; i++ {
		result[i] = int32(i - n/2)
	}
	return result
}

func makeInt64Array(n int) []int64 {
	result := make([]int64, n)
	for i := 0; i < n; i++ {
		result[i] = int64(i - n/2)
	}
	return result
}

func makeFloat32Array(n int) []float32 {
	result := make([]float32, n)
	for i := 0; i < n; i++ {
		result[i] = float32(i) * 1.5
	}
	return result
}

func makeFloat64Array(n int) []float64 {
	result := make([]float64, n)
	for i := 0; i < n; i++ {
		result[i] = float64(i) * 2.5
	}
	return result
}

func makeStringArray(n int) []string {
	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = "test string"
	}
	return result
}

func makeBytesArray(n int) [][]byte {
	result := make([][]byte, n)
	for i := 0; i < n; i++ {
		result[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
	}
	return result
}

// Benchmark tests

func BenchmarkDecodeUint32Array_10(b *testing.B) {
	enc := NewArrayEncoder(256)
	values := makeUint32Array(10)
	encoded := enc.EncodeUint32Array(1, values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeUint32Array(encoded)
	}
}

func BenchmarkDecodeUint32Array_100(b *testing.B) {
	enc := NewArrayEncoder(512)
	values := makeUint32Array(100)
	encoded := enc.EncodeUint32Array(1, values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeUint32Array(encoded)
	}
}

func BenchmarkDecodeUint32Array_1000(b *testing.B) {
	enc := NewArrayEncoder(4096)
	values := makeUint32Array(1000)
	encoded := enc.EncodeUint32Array(1, values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeUint32Array(encoded)
	}
}

func BenchmarkDecodeFloat64Array_100(b *testing.B) {
	enc := NewArrayEncoder(1024)
	values := makeFloat64Array(100)
	encoded := enc.EncodeFloat64Array(1, values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeFloat64Array(encoded)
	}
}

func BenchmarkDecodeStringArray_100(b *testing.B) {
	enc := NewArrayEncoder(2048)
	values := makeStringArray(100)
	encoded := enc.EncodeStringArray(1, values)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeStringArray(encoded)
	}
}

// Round-trip benchmarks (encode + decode)

func BenchmarkRoundTrip_Uint32Array_100(b *testing.B) {
	values := makeUint32Array(100)
	enc := NewArrayEncoder(512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded := enc.EncodeUint32Array(1, values)
		_, _ = DecodeUint32Array(encoded)
		enc.Reset()
	}
}

func BenchmarkRoundTrip_Float64Array_100(b *testing.B) {
	values := makeFloat64Array(100)
	enc := NewArrayEncoder(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded := enc.EncodeFloat64Array(1, values)
		_, _ = DecodeFloat64Array(encoded)
		enc.Reset()
	}
}

func BenchmarkRoundTrip_StringArray_100(b *testing.B) {
	values := makeStringArray(100)
	enc := NewArrayEncoder(2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded := enc.EncodeStringArray(1, values)
		_, _ = DecodeStringArray(encoded)
		enc.Reset()
	}
}
