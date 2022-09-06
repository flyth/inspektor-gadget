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
	"testing"
)

func TestColumnsInvalid(t *testing.T) {
	type testFail1 struct {
		Unknown string `column:"left,unknown"` // unknown parameter
	}
	type testFail2 struct {
		Unknown1 string `column:"unknown"`
		Unknown2 string `column:"unknown"` // double name
	}
	type testFail3 struct {
		testFail2
	}
	_, err := NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
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

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
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

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsFixed(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,fixed"`
	}
	type testFail1 struct {
		Field string `column:"fail,fixed:foo"` // with param
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsGroup(t *testing.T) {
	type testSuccess1 struct {
		FieldInt     int64   `column:"int,group:sum"`
		FieldUint    int64   `column:"uint,group:sum"`
		FieldFloat32 float32 `column:"float32,group:sum"`
		FieldFloat64 float64 `column:"float64,group:sum"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,group"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,group:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,group:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,group:sum:bar"` // double param
	}
	type testFail5 struct {
		Field string `column:"fail,group:sum"` // wrong type
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail5]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsHide(t *testing.T) {
	type testSuccess1 struct {
		Field string `column:"field,hide"`
	}
	type testFail1 struct {
		Field string `column:"fail,hide:foo"` // with param
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsOrder(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,order:4"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,order"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,order:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,order:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,order:sum:bar"` // double param
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsPrecision(t *testing.T) {
	type testSuccess1 struct {
		Float32 float32 `column:"left,precision:2"`
		Float64 float64 `column:"right,precision:2"`
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
		Field float32 `column:"fail,precision:-1"`
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
		Field float64 `column:"fail,precision:-1"`
	}
	type testFail9 struct {
		Field string `column:"fail,precision:2"`
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail5]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail6]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail7]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail8]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail9]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}

func TestColumnsWidth(t *testing.T) {
	type testSuccess1 struct {
		FieldWidth int64 `column:"int,width:4"`
	}
	type testFail1 struct {
		Field int64 `column:"fail,width"` // no param
	}
	type testFail2 struct {
		Field int64 `column:"fail,width:"` // empty param
	}
	type testFail3 struct {
		Field int64 `column:"fail,width:foo"` // invalid param
	}
	type testFail4 struct {
		Field int64 `column:"fail,width:sum:bar"` // double param
	}

	_, err := NewColumns[testSuccess1]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}
	_, err = NewColumns[testFail1]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail2]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail3]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
	_, err = NewColumns[testFail4]()
	if err == nil {
		t.Errorf("succeeded to initialize but expected error")
	}
}
