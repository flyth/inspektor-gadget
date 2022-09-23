// Copyright 2019-2022 The Inspektor Gadget authors
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

package types

import (
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Pid       uint32   `json:"pid,omitempty" column:"pid,minWidth:7"`
	Ppid      uint32   `json:"ppid,omitempty" column:"ppid,minWidth:7"`
	Comm      string   `json:"pcomm,omitempty" column:"comm,width:16,fixed"`
	Retval    int      `json:"ret,omitempty" column:"ret,width:3,fixed"`
	Args      []string `json:"args,omitempty" column:"args,width:40"`
	UID       uint32   `json:"uid,omitempty" column:"uid,minWidth:10,hide"`
	MountNsID uint64   `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
}

func GetColumns() *columns.Columns[Event] {
	execColumns := columns.MustCreateColumns[Event]()

	execColumns.MustSetExtractor("args", func(event *Event) (ret string) {
		return strings.Join(event.Args, " ")
	})

	return execColumns
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}
