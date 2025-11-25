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

package wasm

import (
	"context"
	"encoding/json"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (i *wasmOperatorInstance) addFieldFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "fieldGetScalar", i.fieldGetScalar,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
			wapi.ValueTypeI32, // Error Pointer
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // Value
	)

	exportFunction(env, "fieldGetBuffer", i.fieldGetBuffer,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
			wapi.ValueTypeI64, // Dest buffer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // N bytes or Error
	)

	exportFunction(env, "fieldSet", i.fieldSet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
			wapi.ValueTypeI64, // Value
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "fieldAddTag", i.fieldAddTag,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI64, // Tag
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "fieldGetStruct", i.fieldGetStruct,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI64, // Dest buffer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // N bytes or Error
	)

	exportFunction(env, "fieldPutStruct", i.fieldPutStruct,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI64, // Source buffer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)

	exportFunction(env, "fieldGetStructArray", i.fieldGetStructArray,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI64, // Dest buffer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // N bytes or Error
	)

	exportFunction(env, "fieldPutStructArray", i.fieldPutStructArray,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI64, // Source buffer
		},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Error
	)
}

func (i *wasmOperatorInstance) getDataFromDatasourceHandle(dataHandle uint32) (datasource.Data, bool) {
	if !isDataArrayHandle(dataHandle) {
		return getHandle[datasource.Data](i, dataHandle)
	}

	dataArrayHandle := dataHandle & 0xffff

	dataArray, ok := getHandle[datasource.DataArray](i, dataArrayHandle)
	if !ok {
		return nil, false
	}
	data := dataArray.Get(getIndexFromDataArrayHandle(dataHandle))
	return data, data != nil
}

// fieldGetScalar returns the field's value for scalar fields.
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// - stack[3]: Error Pointer. It's set to 1 if an error happened.
// Return value:
// - Field's value
func (i *wasmOperatorInstance) fieldGetScalar(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	fieldKind := api.Kind(wapi.DecodeU32(stack[2]))
	errPtr := wapi.DecodeU32(stack[3])

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		i.writeErrToGuest(ctx, 1, errPtr)
		return
	}
	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		i.writeErrToGuest(ctx, 1, errPtr)
		return
	}

	var val uint64
	var err error

	switch fieldKind {
	case api.Kind_Bool:
		var ret bool
		ret, err = field.Bool(data)
		if ret {
			val = 1
		} else {
			val = 0
		}
	case api.Kind_Int8:
		var ret int8
		ret, err = field.Int8(data)
		val = uint64(ret)
	case api.Kind_Int16:
		var ret int16
		ret, err = field.Int16(data)
		val = uint64(ret)
	case api.Kind_Int32:
		var ret int32
		ret, err = field.Int32(data)
		val = uint64(ret)
	case api.Kind_Int64:
		var ret int64
		ret, err = field.Int64(data)
		val = uint64(ret)
	case api.Kind_Uint8:
		var ret uint8
		ret, err = field.Uint8(data)
		val = uint64(ret)
	case api.Kind_Uint16:
		var ret uint16
		ret, err = field.Uint16(data)
		val = uint64(ret)
	case api.Kind_Uint32:
		var ret uint32
		ret, err = field.Uint32(data)
		val = uint64(ret)
	case api.Kind_Uint64:
		val, err = field.Uint64(data)
	// The guest has to pass floats using the IEEE 754 binary representation
	case api.Kind_Float32:
		var ret uint32
		ret, err = field.Uint32(data)
		val = uint64(ret)
	case api.Kind_Float64:
		val, err = field.Uint64(data)
	case api.Kind_String, api.Kind_Bytes:
		i.logger.Warnf("fieldGetScalar: field kind %q not supported, use fieldGetBuffer instead()", fieldKind)
		i.writeErrToGuest(ctx, 1, errPtr)
		return
	default:
		i.logger.Warnf("unknown field kind: %d", stack[2])
		i.writeErrToGuest(ctx, 1, errPtr)
		return
	}

	if err != nil {
		i.logger.Warnf("fieldGetScalar for field %q failed: %v", field.Name(), err)
		i.writeErrToGuest(ctx, 1, errPtr)
		return
	}

	stack[0] = val
}

// fieldGetBuffer returns the field's value for string and bytes fields.
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// - stack[3]: Destination buffer
// Return value:
// - The number of bytes copied or -1 in case of error
func (i *wasmOperatorInstance) fieldGetBuffer(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	fieldKind := api.Kind(wapi.DecodeU32(stack[2]))
	dst := stack[3]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}
	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	switch fieldKind {
	case api.Kind_String, api.Kind_Bytes:
		bytes := field.Get(data)
		if err := i.writeToDstBuffer(bytes, dst); err != nil {
			i.logger.Warnf("fieldGetBuffer: %v", err)
			stack[0] = wapi.EncodeI32(-1)
			return
		}

		stack[0] = uint64(len(bytes))
	default:
		i.logger.Warnf("unknown field kind: %d", stack[2])
		stack[0] = wapi.EncodeI32(-1)
	}
}

// fieldSet sets the field's value
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// - stack[3]: Value to store
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) fieldSet(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	fieldKind := api.Kind(wapi.DecodeU32(stack[2]))
	value := stack[3]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 1
		return
	}
	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = 1
		return
	}

	var err error

	switch fieldKind {
	case api.Kind_Bool:
		err = field.PutBool(data, value != 0)
	case api.Kind_Int8:
		err = field.PutInt8(data, int8(value))
	case api.Kind_Int16:
		err = field.PutInt16(data, int16(value))
	case api.Kind_Int32:
		err = field.PutInt32(data, int32(value))
	case api.Kind_Int64:
		err = field.PutInt64(data, int64(value))
	case api.Kind_Uint8:
		err = field.PutUint8(data, uint8(value))
	case api.Kind_Uint16:
		err = field.PutUint16(data, uint16(value))
	case api.Kind_Uint32:
		err = field.PutUint32(data, uint32(value))
	case api.Kind_Uint64:
		err = field.PutUint64(data, uint64(value))
	case api.Kind_Float32:
		// The guest has to pass it using the IEEE 754 binary representation
		err = field.PutUint32(data, uint32(value))
	case api.Kind_Float64:
		err = field.PutUint64(data, uint64(value))
	case api.Kind_String:
		var str string
		str, err = stringFromStack(m, value)
		if err != nil {
			i.logger.Warnf("fieldSet: reading string from stack: %v", err)
			stack[0] = 1
			return
		}
		err = field.PutString(data, str)
	case api.Kind_Bytes:
		var buf []byte
		buf, err = bufFromStack(m, value)
		if err != nil {
			i.logger.Warnf("reading bytes from stack: %v", err)
			stack[0] = 1
			return
		}
		err = field.PutBytes(data, buf)
	default:
		i.logger.Warnf("unknown field kind: %d", uint32(stack[2]))
		stack[0] = 1
		return
	}

	if err != nil {
		i.logger.Warnf("fieldSet for field %q failed: %v", field.Name(), err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// fieldAddTag adds a tag to the field
// Params:
// - stack[0]: Field handle
// - stack[1]: Tag to add
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) fieldAddTag(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	tagPtr := stack[1]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 1
		return
	}
	tag, err := stringFromStack(m, tagPtr)
	if err != nil {
		i.logger.Warnf("fieldAddTag: reading string from stack: %v", err)
		stack[0] = 1
		return
	}

	field.AddTags(tag)
	stack[0] = 0
}

// fieldGetStruct retrieves a struct field as JSON
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Destination buffer
// Return value:
// - The number of bytes copied or -1 in case of error
func (i *wasmOperatorInstance) fieldGetStruct(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	dst := stack[2]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	// Get struct as map
	structVal, err := field.GetStruct(data)
	if err != nil {
		i.logger.Warnf("fieldGetStruct for field %q failed: %v", field.Name(), err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	// Serialize to JSON for WASM consumption
	jsonBytes, err := json.Marshal(structVal)
	if err != nil {
		i.logger.Warnf("fieldGetStruct: marshaling JSON: %v", err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	if err := i.writeToDstBuffer(jsonBytes, dst); err != nil {
		i.logger.Warnf("fieldGetStruct: %v", err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	stack[0] = uint64(len(jsonBytes))
}

// fieldPutStruct sets a struct field from JSON
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Source buffer (JSON data)
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) fieldPutStruct(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	src := stack[2]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 1
		return
	}

	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = 1
		return
	}

	// Read JSON from WASM memory
	jsonBytes, err := bufFromStack(m, src)
	if err != nil {
		i.logger.Warnf("fieldPutStruct: reading buffer: %v", err)
		stack[0] = 1
		return
	}

	// Parse JSON to map
	var structVal map[string]any
	if err := json.Unmarshal(jsonBytes, &structVal); err != nil {
		i.logger.Warnf("fieldPutStruct: unmarshaling JSON: %v", err)
		stack[0] = 1
		return
	}

	// Set struct
	if err := field.PutStruct(data, structVal); err != nil {
		i.logger.Warnf("fieldPutStruct for field %q failed: %v", field.Name(), err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}

// fieldGetStructArray retrieves a struct array field as JSON
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Destination buffer
// Return value:
// - The number of bytes copied or -1 in case of error
func (i *wasmOperatorInstance) fieldGetStructArray(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	dst := stack[2]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	// Get struct array
	structArr, err := field.GetStructArray(data)
	if err != nil {
		i.logger.Warnf("fieldGetStructArray for field %q failed: %v", field.Name(), err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	// Serialize to JSON for WASM consumption
	jsonBytes, err := json.Marshal(structArr)
	if err != nil {
		i.logger.Warnf("fieldGetStructArray: marshaling JSON: %v", err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	if err := i.writeToDstBuffer(jsonBytes, dst); err != nil {
		i.logger.Warnf("fieldGetStructArray: %v", err)
		stack[0] = wapi.EncodeI32(-1)
		return
	}

	stack[0] = uint64(len(jsonBytes))
}

// fieldPutStructArray sets a struct array field from JSON
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Source buffer (JSON data)
// Return value:
// - 0 on success, 1 on error
func (i *wasmOperatorInstance) fieldPutStructArray(ctx context.Context, m wapi.Module, stack []uint64) {
	fieldHandle := wapi.DecodeU32(stack[0])
	dataHandle := wapi.DecodeU32(stack[1])
	src := stack[2]

	field, ok := getHandle[datasource.FieldAccessor](i, fieldHandle)
	if !ok {
		stack[0] = 1
		return
	}

	data, ok := i.getDataFromDatasourceHandle(dataHandle)
	if !ok {
		stack[0] = 1
		return
	}

	// Read JSON from WASM memory
	jsonBytes, err := bufFromStack(m, src)
	if err != nil {
		i.logger.Warnf("fieldPutStructArray: reading buffer: %v", err)
		stack[0] = 1
		return
	}

	// Parse JSON to array of maps
	var structArr []map[string]any
	if err := json.Unmarshal(jsonBytes, &structArr); err != nil {
		i.logger.Warnf("fieldPutStructArray: unmarshaling JSON: %v", err)
		stack[0] = 1
		return
	}

	// Set struct array
	if err := field.PutStructArray(data, structArr); err != nil {
		i.logger.Warnf("fieldPutStructArray for field %q failed: %v", field.Name(), err)
		stack[0] = 1
		return
	}

	stack[0] = 0
}
