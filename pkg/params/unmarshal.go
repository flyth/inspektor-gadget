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

package params

import (
	"reflect"
	"strings"
)

func (p *Params) Unmarshal(target any) {
	pm := p.ParamMap()
	v := reflect.ValueOf(target)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		fieldName := strings.ToLower(v.Type().Field(i).Name)
		if v.Type().Field(i).Tag.Get("param") != "" {
			fieldName = v.Type().Field(i).Tag.Get("param")
		}
		val, ok := pm[fieldName]
		if !ok {
			continue
		}

		f := v.Field(i)
		switch f.Type().Kind() {
		case reflect.String:
			StringAsString(val, f.Addr().Interface().(*string))
		case reflect.Bool:
			StringAsBool(val, f.Addr().Interface().(*bool))
		case reflect.Uint:
			StringAsUint(val, f.Addr().Interface().(*uint))
		case reflect.Uint8:
			StringAsUint(val, f.Addr().Interface().(*uint8))
		case reflect.Uint16:
			StringAsUint(val, f.Addr().Interface().(*uint16))
		case reflect.Uint32:
			StringAsUint(val, f.Addr().Interface().(*uint32))
		case reflect.Uint64:
			StringAsUint(val, f.Addr().Interface().(*uint64))
		case reflect.Int:
			StringAsInt(val, f.Addr().Interface().(*int))
		case reflect.Int8:
			StringAsInt(val, f.Addr().Interface().(*int8))
		case reflect.Int16:
			StringAsInt(val, f.Addr().Interface().(*int16))
		case reflect.Int32:
			StringAsInt(val, f.Addr().Interface().(*int32))
		case reflect.Int64:
			StringAsInt(val, f.Addr().Interface().(*int64))
		case reflect.Float32:
			StringAsFloat(val, f.Addr().Interface().(*float32))
		case reflect.Float64:
			StringAsFloat(val, f.Addr().Interface().(*float64))
		}
	}
}
