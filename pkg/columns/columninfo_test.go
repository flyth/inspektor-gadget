// Copyright 2022 The Inspektor Gadget authors
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

package columns

import (
	"reflect"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/columns/ellipsis"
)

func initializeColumns[T any](t *testing.T, expectSuccess bool, name string, options ...Option) *Columns[T] {
	cols, err := NewColumns[T](options...)
	t.Run(name, func(t *testing.T) {
		if err != nil && expectSuccess {
			t.Fatalf("failed to initialize: %v", err)
		}
		if err == nil && !expectSuccess {
			t.Errorf("succeeded to initialize but expected error")
		}
	})
	return cols
}

func expectColumnsSuccess[T any](t *testing.T, options ...Option) *Columns[T] {
	return initializeColumns[T](t, true, "success", options...)
}

func expectColumnsFail[T any](t *testing.T, name string, options ...Option) *Columns[T] {
	return initializeColumns[T](t, false, name, options...)
}

func expectColumn[T any](t *testing.T, cols *Columns[T], columnName string) *Column[T] {
	col, ok := cols.GetColumn(columnName)
	if !ok {
		t.Fatalf("expected column with name %q", columnName)
	}
	return col
}

func expectColumnValue[T any](t *testing.T, col *Column[T], fieldName string, expectedValue interface{}) {
	columnValue := reflect.ValueOf(col).Elem()
	fieldValue := columnValue.FieldByName(fieldName)
	if !fieldValue.IsValid() {
		t.Errorf("expected field %q", fieldName)
		return
	}
	if fieldValue.Interface() != expectedValue {
		t.Errorf("expected field %q to equal %+v, got %+v", fieldName, expectedValue, fieldValue.Interface())
	}
}

func TestColumnsInvalid(t *testing.T) {
	type testFail1 struct {
		Unknown string `column:"left,unknown"`
	}
	type testFail2 struct {
		Unknown1 string `column:"unknown"`
		Unknown2 string `column:"unknown"`
	}
	type testFail3 struct {
		testFail2
	}
	expectColumnsFail[testFail1](t, "unknown parameter")
	expectColumnsFail[testFail2](t, "double name")
	expectColumnsFail[testFail3](t, "nested double name")
}

func TestColumnsAlign(t *testing.T) {
	type testSuccess1 struct {
		AlignLeft  string `column:"left,align:left"`
		AlignRight string `column:"right,align:right"`
	}
	type testFail1 struct {
		Field string `column:"fail,align"`
	}
	type testFail2 struct {
		Field string `column:"fail,align:"`
	}
	type testFail3 struct {
		Field string `column:"fail,align:foo"`
	}
	type testFail4 struct {
		Field string `column:"fail,align:left:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "left"), "Alignment", AlignLeft)
	expectColumnValue(t, expectColumn(t, cols, "right"), "Alignment", AlignRight)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
}

func TestColumnsEllipsis(t *testing.T) {
	type testSuccess1 struct {
		EllipsisEmpty      string `column:"empty,ellipsis"`
		EllipsisEmptyColon string `column:"emptyColon,ellipsis:"`
		EllipsisNone       string `column:"none,ellipsis:none"`
		EllipsisStart      string `column:"start,ellipsis:start"`
		EllipsisEnd        string `column:"end,ellipsis:end"`
		EllipsisMiddle     string `column:"middle,ellipsis:middle"`
	}
	type testFail1 struct {
		Field string `column:"fail,ellipsis:foo"`
	}
	type testFail2 struct {
		Field string `column:"fail,ellipsis:left:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "empty"), "EllipsisType", cols.options.DefaultEllipsis)
	expectColumnValue(t, expectColumn(t, cols, "emptyColon"), "EllipsisType", cols.options.DefaultEllipsis)
	expectColumnValue(t, expectColumn(t, cols, "none"), "EllipsisType", ellipsis.None)
	expectColumnValue(t, expectColumn(t, cols, "start"), "EllipsisType", ellipsis.Start)
	expectColumnValue(t, expectColumn(t, cols, "end"), "EllipsisType", ellipsis.End)
	expectColumnValue(t, expectColumn(t, cols, "middle"), "EllipsisType", ellipsis.Middle)

	expectColumnsFail[testFail1](t, "invalid parameter")
	expectColumnsFail[testFail2](t, "double parameter")
}

func TestColumnsFixed(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,fixed"`
	}
	type testFail1 struct {
		Field string `column:"fail,fixed:foo"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)
	expectColumnValue(t, expectColumn(t, cols, "field"), "FixedWidth", true)

	expectColumnsFail[testFail1](t, "invalid parameter")
}

func TestColumnsGroup(t *testing.T) {
	type testSuccess1 struct {
		FieldInt     int64   `column:"int,group:sum"`
		FieldUint    int64   `column:"uint,group:sum"`
		FieldFloat32 float32 `column:"float32,group:sum"`
		FieldFloat64 float64 `column:"float64,group:sum"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,group"`
	}
	type testFail2 struct {
		Field int64 `column:"fail,group:"`
	}
	type testFail3 struct {
		Field int64 `column:"fail,group:foo"`
	}
	type testFail4 struct {
		Field int64 `column:"fail,group:sum:bar"`
	}
	type testFail5 struct {
		Field string `column:"fail,group:sum"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "uint"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "float32"), "GroupType", GroupTypeSum)
	expectColumnValue(t, expectColumn(t, cols, "float64"), "GroupType", GroupTypeSum)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
	expectColumnsFail[testFail5](t, "wrong type")
}

func TestColumnsHide(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,hide"`
	}
	type testFail1 struct {
		Field string `column:"fail,hide:foo"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "field"), "Visible", false)

	expectColumnsFail[testFail1](t, "invalid parameter")
}

func TestColumnsOrder(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,order:4"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,order"`
	}
	type testFail2 struct {
		Field int64 `column:"fail,order:"`
	}
	type testFail3 struct {
		Field int64 `column:"fail,order:foo"`
	}
	type testFail4 struct {
		Field int64 `column:"fail,order:sum:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "Order", 4)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
}

func TestColumnsPrecision(t *testing.T) {
	type testSuccess1 struct {
		Float32 float32 `column:"float32,precision:4"`
		Float64 float64 `column:"float64,precision:4"`
	}
	type testFail1 struct {
		Field1 float32 `column:"fail,precision"`
	}
	type testFail2 struct {
		Field float32 `column:"fail,precision:"`
	}
	type testFail3 struct {
		Field float32 `column:"fail,precision:foo"`
	}
	type testFail4 struct {
		Field float32 `column:"fail,precision:-2"`
	}
	type testFail5 struct {
		Field1 float64 `column:"fail,precision"`
	}
	type testFail6 struct {
		Field float64 `column:"fail,precision:"`
	}
	type testFail7 struct {
		Field float64 `column:"fail,precision:foo"`
	}
	type testFail8 struct {
		Field float64 `column:"fail,precision:-2"`
	}
	type testFail9 struct {
		Field string `column:"fail,precision:2"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "float32"), "Precision", 4)
	expectColumnValue(t, expectColumn(t, cols, "float64"), "Precision", 4)

	expectColumnsFail[testFail1](t, "float32: missing parameter")
	expectColumnsFail[testFail2](t, "float32: empty parameter")
	expectColumnsFail[testFail3](t, "float32: invalid parameter")
	expectColumnsFail[testFail4](t, "float32: double parameter")
	expectColumnsFail[testFail5](t, "float64: missing parameter")
	expectColumnsFail[testFail6](t, "float64: empty parameter")
	expectColumnsFail[testFail7](t, "float64: invalid parameter")
	expectColumnsFail[testFail8](t, "float64: double parameter")
	expectColumnsFail[testFail9](t, "invalid field")
}

func TestColumnsWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth     int64 `column:"int,width:4"`
		FieldWidthType int64 `column:"intType,width:type"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,width"`
	}
	type testFail2 struct {
		Field int64 `column:"fail,width:"`
	}
	type testFail3 struct {
		Field int64 `column:"fail,width:foo"`
	}
	type testFail4 struct {
		Field int64 `column:"fail,width:sum:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "Width", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "Width", MaxCharsInt64)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
}

func TestColumnsMaxWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldMaxWidth     int64 `column:"int,maxWidth:4"`
		FieldMaxWidthType int64 `column:"intType,maxWidth:type"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,maxWidth"`
	}
	type testFail2 struct {
		Field int64 `column:"fail,maxWidth:"`
	}
	type testFail3 struct {
		Field int64 `column:"fail,maxWidth:foo"`
	}
	type testFail4 struct {
		Field int64 `column:"fail,maxWidth:sum:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "MaxWidth", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "MaxWidth", MaxCharsInt64)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
}

func TestColumnsMinWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldMinWidth     int64 `column:"int,minWidth:4"`
		FieldMaxWidthType int64 `column:"intType,minWidth:type"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,minWidth"`
	}
	type testFail2 struct {
		Field int64 `column:"fail,minWidth:"`
	}
	type testFail3 struct {
		Field int64 `column:"fail,minWidth:foo"`
	}
	type testFail4 struct {
		Field int64 `column:"fail,minWidth:sum:bar"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	expectColumnValue(t, expectColumn(t, cols, "int"), "MinWidth", 4)
	expectColumnValue(t, expectColumn(t, cols, "intType"), "MinWidth", MaxCharsInt64)

	expectColumnsFail[testFail1](t, "missing parameter")
	expectColumnsFail[testFail2](t, "empty parameter")
	expectColumnsFail[testFail3](t, "invalid parameter")
	expectColumnsFail[testFail4](t, "double parameter")
}

func TestColumnsWidthFromType(t *testing.T) {
	type testSuccess1 struct {
		Int8   int8   `column:",minWidth:type,maxWidth:type,width:type"`
		Int16  int16  `column:",minWidth:type,maxWidth:type,width:type"`
		Int32  int32  `column:",minWidth:type,maxWidth:type,width:type"`
		Int64  int64  `column:",minWidth:type,maxWidth:type,width:type"`
		Uint8  uint8  `column:",minWidth:type,maxWidth:type,width:type"`
		Uint16 uint16 `column:",minWidth:type,maxWidth:type,width:type"`
		Uint32 uint32 `column:",minWidth:type,maxWidth:type,width:type"`
		Uint64 uint64 `column:",minWidth:type,maxWidth:type,width:type"`
	}

	type testFail1 struct {
		String string `column:",minWidth:type,maxWidth:type,width:type"`
	}

	cols := expectColumnsSuccess[testSuccess1](t)

	col := expectColumn(t, cols, "int8")
	expectColumnValue(t, col, "Width", MaxCharsInt8)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt8)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt8)

	col = expectColumn(t, cols, "int16")
	expectColumnValue(t, col, "Width", MaxCharsInt16)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt16)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt16)

	col = expectColumn(t, cols, "int32")
	expectColumnValue(t, col, "Width", MaxCharsInt32)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt32)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt32)

	col = expectColumn(t, cols, "int64")
	expectColumnValue(t, col, "Width", MaxCharsInt64)
	expectColumnValue(t, col, "MinWidth", MaxCharsInt64)
	expectColumnValue(t, col, "MaxWidth", MaxCharsInt64)

	col = expectColumn(t, cols, "uint8")
	expectColumnValue(t, col, "Width", MaxCharsUint8)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint8)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint8)

	col = expectColumn(t, cols, "uint16")
	expectColumnValue(t, col, "Width", MaxCharsUint16)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint16)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint16)

	col = expectColumn(t, cols, "uint32")
	expectColumnValue(t, col, "Width", MaxCharsUint32)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint32)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint32)

	col = expectColumn(t, cols, "uint64")
	expectColumnValue(t, col, "Width", MaxCharsUint64)
	expectColumnValue(t, col, "MinWidth", MaxCharsUint64)
	expectColumnValue(t, col, "MaxWidth", MaxCharsUint64)

	expectColumnsFail[testFail1](t, "invalid field type")
}

func TestWithoutColumnTag(t *testing.T) {
	type Main struct {
		StringField string
		IntField    int
	}

	cols := expectColumnsSuccess[Main](t, WithRequireColumnDefinition(false))

	expectColumn(t, cols, "StringField")
}

func TestColumnFilters(t *testing.T) {
	type Embedded struct {
		EmbeddedString string `column:"embeddedString" columnTags:"test"`
	}
	type Main struct {
		Embedded
		MainString string `column:"mainString" columnTags:"test2"`
		NoTags     string `column:"noTags"`
	}

	cols := expectColumnsSuccess[Main](t)

	expectColumn := func(columnName string, name string, filters ...ColumnFilter) {
		t.Run(name, func(t *testing.T) {
			colMap := cols.GetColumnMap(filters...)
			if _, ok := colMap.GetColumn(columnName); !ok {
				t.Errorf("expected column %q to exist after applying filters", columnName)
			}
		})
	}

	expectColumn("embeddedString", "embedded or WithTag(test)", Or(WithEmbedded(true), WithTag("test")))
	expectColumn("mainString", "not embedded or WithoutTag(test)", Or(WithEmbedded(false), WithoutTag("test")))
	expectColumn("mainString", "WithTags(test2) and WithoutTags(test)", And(WithTags([]string{"test2"}), WithoutTags([]string{"test"})))
	expectColumn("mainString", "WithTags(test2) and WithoutTags(test)", And(WithTags([]string{"test2"}), WithoutTags([]string{"test"})))

	orderedColumns := cols.GetOrderedColumns(WithoutTags([]string{"test"})) // missing path
	if len(orderedColumns) != 2 || orderedColumns[0].Name != "mainString" {
		t.Errorf("expected a mainString column after getting ordered columns using filters")
	}

	orderedColumns = cols.GetOrderedColumns(WithNoTags())
	if len(orderedColumns) != 1 || orderedColumns[0].Name != "noTags" {
		t.Errorf("expected a noTags column after getting ordered columns using filters")
	}
}

func TestColumnMatcher(t *testing.T) {
	type Embedded struct {
		EmbeddedString string `column:"embeddedString" columnTags:"test"`
	}
	type Main struct {
		Embedded
		MainString string `column:"mainString" columnTags:"test2"`
	}

	cols := expectColumnsSuccess[Main](t)

	c := expectColumn(t, cols, "embeddedString")
	if !c.IsEmbedded() {
		t.Errorf("expected the embedded field to be identified as embedded")
	}
	if !c.HasTag("test") {
		t.Errorf("expected the embedded field to have tag 'test'")
	}
	if c.HasTag("test2") {
		t.Errorf("didn't expect the embedded field to have tag 'test2'")
	}

	c = expectColumn(t, cols, "mainString")
	if c.IsEmbedded() {
		t.Errorf("expected mainString to not be identified as embedded")
	}
	if !c.HasTag("test2") {
		t.Errorf("expected mainString to have tag 'test2'")
	}
	if c.HasTag("test") {
		t.Errorf("didn't expect mainString to have tag 'test'")
	}
}
