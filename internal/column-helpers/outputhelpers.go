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

package columnhelpers

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

// TextColumnsFormatter is the interface used for outputHelper
type TextColumnsFormatter interface {
	FormatHeader() string
	TransformEvent(string) (string, error)
	EventHandlerFunc() any
	EventHandlerFuncArray() any
	SetEventCallback(eventCallback func(string))
	SetBufferSize(int)
	GetCell(row, column int) (string, int)
	GetNumRows() int
	GetNumColumns() int
}

// outputHelpers hides all information about underlying types from the application
type outputHelper[T any] struct {
	ch *ColumnHelpers[T]
	*textcolumns.TextColumnsFormatter[T]
	eventCallback func(string)
	bufferSize    int
	buffer        []*T
	bufferIndex   int
}

func (oh *outputHelper[T]) EventHandlerFunc() any {
	if oh.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from TextColumnsFormatter")
	}
	return func(ev *T) {
		if oh.bufferSize > 0 {
			oh.buffer[oh.bufferIndex] = ev
			oh.bufferIndex = (oh.bufferIndex + 1) % oh.bufferSize
		}
		oh.eventCallback(oh.TextColumnsFormatter.FormatEntry(ev))
	}
}

func (oh *outputHelper[T]) EventHandlerFuncArray() any {
	if oh.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from TextColumnsFormatter")
	}
	return func(events []*T) {
		oh.eventCallback(oh.TextColumnsFormatter.FormatTable(events))
	}
}

func (oh *outputHelper[T]) SetEventCallback(eventCallback func(string)) {
	oh.eventCallback = eventCallback
}

// TransformEvent takes a JSON encoded line and transforms it to columns view
func (oh *outputHelper[T]) TransformEvent(line string) (string, error) {
	ev := new(T)
	err := json.Unmarshal([]byte(line), &ev)
	if err != nil {
		return "", err
	}

	// Apply filters
	if oh.ch.filterSpec != nil {
		if !oh.ch.filterSpec.Match(ev) {
			return "", nil
		}
	}

	return oh.FormatEntry(ev), nil
}

func (oh *outputHelper[T]) WriteEvent(event any) {
	if ev, ok := event.(*T); ok {
		// Apply filters
		if oh.ch.filterSpec != nil {
			if !oh.ch.filterSpec.Match(ev) {
				return
			}
		}
		fmt.Fprint(os.Stdout, oh.FormatEntry(ev))
	} else {
		fmt.Fprintf(os.Stderr, "unexpected event of type %v received", reflect.TypeOf(event))
	}
}

func (oh *outputHelper[T]) SetBufferSize(bufferSize int) {
	oh.bufferSize = bufferSize
	if oh.bufferSize > 0 {
		oh.buffer = make([]*T, oh.bufferSize)
		oh.bufferIndex = 0
	}
}

func (oh *outputHelper[T]) GetCell(row, column int) (string, int) {
	if oh.bufferSize == 0 {
		return "", 0
	}
	return oh.TextColumnsFormatter.FormatColumn(oh.buffer[(oh.bufferIndex+row)%oh.bufferSize], column)
}

func (oh *outputHelper[T]) GetNumRows() int {
	return oh.bufferSize
}

func (oh *outputHelper[T]) GetNumColumns() int {
	return len(oh.TextColumnsFormatter.GetColumns())
}
