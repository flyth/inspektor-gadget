// Copyright 2023 The Inspektor Gadget authors
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

package btfutils

import (
	"reflect"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

const (
	BTFTypePrefix = "btftype_"
)

func GetFieldsFromBTF(vStruct *btf.Struct) ([]columns.DynamicField, error) {
	fields := make([]columns.DynamicField, 0, len(vStruct.Members))
	for i := range vStruct.Members {
		member := vStruct.Members[i]
		rType, tags := getType(member.Type)
		if rType == nil {
			continue
		}
		attrs := &columns.Attributes{
			Name: member.Name,
			Tags: tags,
		}
		fields = append(fields, columns.DynamicField{
			Attributes: attrs,
			Type:       rType,
			Offset:     uintptr(member.Offset.Bytes()),
		})
	}
	return fields, nil
}

func getType(typ btf.Type) (reflect.Type, []string) {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType, types := getSimpleType(typedMember.Type)
		return reflect.ArrayOf(int(typedMember.Nelems), arrType), types
	default:
		return getSimpleType(typ)
	}
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

func getSimpleType(typ btf.Type) (reflect.Type, []string) {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(int8(0)), nil
			case 2:
				return reflect.TypeOf(int16(0)), nil
			case 4:
				return reflect.TypeOf(int32(0)), nil
			case 8:
				return reflect.TypeOf(int64(0)), nil
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(uint8(0)), nil
			case 2:
				return reflect.TypeOf(uint16(0)), nil
			case 4:
				return reflect.TypeOf(uint32(0)), nil
			case 8:
				return reflect.TypeOf(uint64(0)), nil
			}
		case btf.Bool:
			return reflect.TypeOf(false), nil
		case btf.Char:
			return reflect.TypeOf(uint8(0)), nil
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return reflect.TypeOf(float32(0)), nil
		case 8:
			return reflect.TypeOf(float64(0)), nil
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		nType, types := getSimpleType(typ)
		return nType, append(types, BTFTypePrefix+typ.TypeName())
	}
	return nil, nil
}
