# Protobuf Wire Format Conventions for Dynamic Fields

This document specifies the protobuf wire format encoding conventions used for complex field types (arrays and structs) in Inspektor Gadget's datasource model.

## Overview

The datasource uses protobuf wire format encoding for:
- **Dynamic arrays** - Variable-length arrays created by operators (not from eBPF)
- **Struct fields** - Complex structures with multiple members
- **Arrays of structs** - Repeated structured data

**Note:** Static arrays from eBPF use zero-copy via `unsafe.Slice` and do NOT use protobuf encoding for performance.

## Wire Format Conventions

### Field Numbering

All encoded data uses **field number 1** as the primary field. This convention simplifies encoding/decoding and ensures consistency.

For struct members, field numbers follow BTF field order:
- First struct member → field number 1
- Second struct member → field number 2
- Third struct member → field number 3
- etc.

### Byte Order

Protobuf handles byte order internally:
- **Varint encoding** - Variable-length integers (int32, int64, uint32, uint64 when small)
- **Fixed32** - Little-endian 4-byte encoding (uint32, int32, float32)
- **Fixed64** - Little-endian 8-byte encoding (uint64, int64, float64)

The encoder/decoder libraries handle byte order conversion automatically.

## Scalar Arrays

Scalar arrays use **packed repeated fields** for efficiency.

### Format Structure

```
[tag] [length] [value1] [value2] ... [valueN]
```

Where:
- `tag` = (field_number << 3) | wire_type (wire_type = 2 for length-delimited)
- `length` = byte length of all packed values (varint encoded)
- `values` = concatenated encoded values

### Integer Arrays (Packed Varint)

Used for: `int32`, `int64`, `uint32`, `uint64` (when values are typically small)

**Example: []int32{1, 2, 3}**
```
0x0A              // Tag: field=1, wire_type=2 (length-delimited)
0x03              // Length: 3 bytes
0x01 0x02 0x03    // Values: varint encoded
```

### Fixed Integer Arrays (Packed Fixed)

Used for: `uint32`, `uint64`, `int32`, `int64` (when using fixed encoding), `float32`, `float64`

**Example: []uint32{100, 200, 300} (as fixed32)**
```
0x0A                              // Tag: field=1, wire_type=2
0x0C                              // Length: 12 bytes (3 * 4)
0x64 0x00 0x00 0x00              // 100 (little-endian fixed32)
0xC8 0x00 0x00 0x00              // 200 (little-endian fixed32)
0x2C 0x01 0x00 0x00              // 300 (little-endian fixed32)
```

**Example: []float64{1.5, 2.5, 3.5}**
```
0x0A                                          // Tag: field=1, wire_type=2
0x18                                          // Length: 24 bytes (3 * 8)
0x00 0x00 0x00 0x00 0x00 0x00 0xF8 0x3F      // 1.5 (IEEE 754 double)
0x00 0x00 0x00 0x00 0x00 0x00 0x04 0x40      // 2.5
0x00 0x00 0x00 0x00 0x00 0x00 0x0C 0x40      // 3.5
```

### String Arrays (Non-Packed)

Strings cannot be packed because each string needs its own length prefix.

**Example: []string{"foo", "bar"}**
```
0x0A              // Tag: field=1, wire_type=2
0x03              // Length: 3 bytes
0x66 0x6F 0x6F    // "foo"
0x0A              // Tag: field=1, wire_type=2 (repeated)
0x03              // Length: 3 bytes
0x62 0x61 0x72    // "bar"
```

### Byte Arrays (Non-Packed)

Each byte slice is length-prefixed.

**Example: [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}}**
```
0x0A              // Tag: field=1, wire_type=2
0x02              // Length: 2 bytes
0x01 0x02         // First byte slice
0x0A              // Tag: field=1, wire_type=2 (repeated)
0x03              // Length: 3 bytes
0x03 0x04 0x05    // Second byte slice
```

## Struct Fields

Struct fields use BTF field order for field numbering.

### Simple Struct Example

Given this eBPF struct:
```c
struct process_info {
    u32 pid;        // Field 1
    u64 timestamp;  // Field 2
    char comm[16];  // Field 3
};
```

Wire format encoding:
```
0x08              // Tag: field=1 (pid), wire_type=0 (varint)
0x7B              // Value: 123 (example PID)
0x10              // Tag: field=2 (timestamp), wire_type=0 (varint)
0x80 0x94 0xEB... // Value: timestamp (varint encoded)
0x1A              // Tag: field=3 (comm), wire_type=2 (length-delimited)
0x04              // Length: 4 bytes
0x62 0x61 0x73 0x68  // "bash"
```

## Arrays of Structs

Arrays of structs use repeated embedded messages, all with field number 1.

### Format Structure

```
[tag] [struct1_length] [struct1_data]
[tag] [struct2_length] [struct2_data]
...
```

### Example: Array of Process Info

**Data: []ProcessInfo{{pid: 123, comm: "bash"}, {pid: 456, comm: "vim"}}**

```
// First struct
0x0A              // Tag: field=1, wire_type=2 (length-delimited message)
0x0A              // Length: 10 bytes for embedded message
  0x08            // Tag: field=1 (pid), wire_type=0
  0x7B            // Value: 123
  0x12            // Tag: field=2 (comm), wire_type=2
  0x04            // Length: 4 bytes
  0x62 0x61 0x73 0x68  // "bash"

// Second struct
0x0A              // Tag: field=1, wire_type=2 (repeated)
0x09              // Length: 9 bytes for embedded message
  0x08            // Tag: field=1 (pid), wire_type=0
  0xC8 0x03       // Value: 456
  0x12            // Tag: field=2 (comm), wire_type=2
  0x03            // Length: 3 bytes
  0x76 0x69 0x6D  // "vim"
```

## Nested Structures

Nested structures use embedded messages with field numbers determined by BTF member order.

### Example: Nested Struct

```c
struct network_event {
    struct process_info proc;  // Field 1 (embedded message)
    u32 src_port;              // Field 2
    u32 dst_port;              // Field 3
};
```

Wire format:
```
0x0A              // Tag: field=1 (proc), wire_type=2 (embedded message)
0x0C              // Length: 12 bytes for embedded message
  [process_info encoding as shown above]
0x10              // Tag: field=2 (src_port), wire_type=0
0x50 0xC3         // Value: 50000 (example)
0x18              // Tag: field=3 (dst_port), wire_type=0
0x50              // Value: 80
```

## Type Mapping

| Go Type | Wire Type | Encoding Method |
|---------|-----------|-----------------|
| `uint32` | 2 (packed) | Fixed32 |
| `uint64` | 2 (packed) | Fixed64 |
| `int32` | 2 (packed) | Fixed32 or varint |
| `int64` | 2 (packed) | Fixed64 or varint |
| `float32` | 2 (packed) | Fixed32 (IEEE 754) |
| `float64` | 2 (packed) | Fixed64 (IEEE 754) |
| `string` | 2 (non-packed) | Length-delimited |
| `[]byte` | 2 (non-packed) | Length-delimited |
| `bool` | 0 | Varint (0 or 1) |

## Implementation Notes

### Encoder (protowire)

The encoder uses `google.golang.org/protobuf/encoding/protowire`:
- `AppendTag(buf, fieldNum, wireType)` - Adds field tag
- `AppendVarint(buf, val)` - Encodes varint
- `AppendFixed32(buf, val)` - Encodes 4-byte value
- `AppendFixed64(buf, val)` - Encodes 8-byte value
- `AppendBytes(buf, val)` - Encodes length-prefixed bytes

### Decoder (protowire)

The decoder uses the same package for low-level parsing:
- `ConsumeTag(buf)` - Reads field number and wire type
- `ConsumeVarint(buf)` - Reads varint
- `ConsumeFixed32(buf)` - Reads 4-byte value
- `ConsumeFixed64(buf)` - Reads 8-byte value
- `ConsumeBytes(buf)` - Reads length-prefixed bytes

### Performance Considerations

1. **Pre-allocation** - Encoder pre-allocates buffer based on expected size
2. **Packed encoding** - Reduces tag overhead for scalar arrays
3. **Zero-copy reads** - Decoder can return slices into the wire format buffer
4. **Reusable buffers** - ArrayEncoder.Reset() allows buffer reuse

## References

- [Protobuf Encoding Guide](https://protobuf.dev/programming-guides/encoding/)
- [protowire package documentation](https://pkg.go.dev/google.golang.org/protobuf/encoding/protowire)
- [Wire Types](https://protobuf.dev/programming-guides/encoding/#structure)
