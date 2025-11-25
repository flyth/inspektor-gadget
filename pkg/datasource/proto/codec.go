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

	"google.golang.org/protobuf/encoding/protowire"
)

// FixedCodec provides encoding/decoding for fixed-width numeric types.
// It uses function pointers for hot-path performance (encode/decode are called per-element).
type FixedCodec[T any] struct {
	// Size is the byte size of each element (4 or 8)
	Size int

	// Encode appends a single value to the buffer and returns the extended buffer.
	// This wraps protowire.AppendFixed32/AppendFixed64.
	Encode func(buf []byte, val T) []byte

	// Decode reads a single value from the buffer and returns (value, bytesConsumed).
	// Returns negative bytesConsumed on error.
	// This wraps protowire.ConsumeFixed32/ConsumeFixed64.
	Decode func(buf []byte) (T, int)
}

// Pre-defined codecs for all fixed-width numeric types.
// These are used by the generic EncodePackedArray and DecodePackedArray functions.
var (
	Uint32Codec = FixedCodec[uint32]{
		Size:   4,
		Encode: protowire.AppendFixed32,
		Decode: protowire.ConsumeFixed32,
	}

	Uint64Codec = FixedCodec[uint64]{
		Size:   8,
		Encode: protowire.AppendFixed64,
		Decode: protowire.ConsumeFixed64,
	}

	Int32Codec = FixedCodec[int32]{
		Size: 4,
		Encode: func(buf []byte, val int32) []byte {
			return protowire.AppendFixed32(buf, uint32(val))
		},
		Decode: func(buf []byte) (int32, int) {
			v, n := protowire.ConsumeFixed32(buf)
			return int32(v), n
		},
	}

	Int64Codec = FixedCodec[int64]{
		Size: 8,
		Encode: func(buf []byte, val int64) []byte {
			return protowire.AppendFixed64(buf, uint64(val))
		},
		Decode: func(buf []byte) (int64, int) {
			v, n := protowire.ConsumeFixed64(buf)
			return int64(v), n
		},
	}

	Float32Codec = FixedCodec[float32]{
		Size: 4,
		Encode: func(buf []byte, val float32) []byte {
			return protowire.AppendFixed32(buf, math.Float32bits(val))
		},
		Decode: func(buf []byte) (float32, int) {
			v, n := protowire.ConsumeFixed32(buf)
			return math.Float32frombits(v), n
		},
	}

	Float64Codec = FixedCodec[float64]{
		Size: 8,
		Encode: func(buf []byte, val float64) []byte {
			return protowire.AppendFixed64(buf, math.Float64bits(val))
		},
		Decode: func(buf []byte) (float64, int) {
			v, n := protowire.ConsumeFixed64(buf)
			return math.Float64frombits(v), n
		},
	}
)

// EncodePackedArray encodes a slice as a packed repeated field.
// Uses the provided codec for element encoding.
//
// Wire format: [tag] [length] [val1] [val2] ... [valN]
// Returns nil for empty slices (consistent with existing encoder behavior).
func EncodePackedArray[T any](buf []byte, fieldNum int, values []T, codec FixedCodec[T]) []byte {
	if len(values) == 0 {
		return nil
	}

	// Tag: field number + wire type 2 (length-delimited)
	buf = protowire.AppendTag(buf, protowire.Number(fieldNum), protowire.BytesType)

	// Length: calculate packed size (use uint64 to avoid overflow on 32-bit)
	packedSize := uint64(len(values)) * uint64(codec.Size)
	buf = protowire.AppendVarint(buf, packedSize)

	// Values: append each using the codec
	for _, v := range values {
		buf = codec.Encode(buf, v)
	}

	return buf
}

// DecodePackedArray decodes a packed repeated field using the provided codec.
// Returns an empty slice for nil/empty input (consistent with encoder behavior).
func DecodePackedArray[T any](data []byte, codec FixedCodec[T]) ([]T, error) {
	if len(data) == 0 {
		return []T{}, nil
	}

	buf := data

	// Consume tag
	_, wt, n := protowire.ConsumeTag(buf)
	if n < 0 {
		return nil, ErrInvalidWireFormat
	}
	if wt != protowire.BytesType {
		return nil, ErrUnexpectedWireType
	}
	buf = buf[n:]

	// Consume length
	length, n := protowire.ConsumeVarint(buf)
	if n < 0 {
		return nil, ErrInvalidWireFormat
	}
	if int(length) > len(buf)-n {
		return nil, ErrInvalidWireFormat
	}
	buf = buf[n:]

	// Validate element count
	numElements := int(length) / codec.Size
	if int(length)%codec.Size != 0 {
		return nil, ErrInvalidWireFormat
	}

	// Decode values
	result := make([]T, numElements)
	for i := 0; i < numElements; i++ {
		val, n := codec.Decode(buf)
		if n < 0 {
			return nil, ErrInvalidWireFormat
		}
		result[i] = val
		buf = buf[n:]
	}

	return result, nil
}
