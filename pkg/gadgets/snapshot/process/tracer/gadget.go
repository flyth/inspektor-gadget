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

package tracer

import (
	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Gadget struct{}

func (g *Gadget) Name() string {
	return "process"
}

func (g *Gadget) Category() string {
	return gadgets.CategorySnapshot
}

func (g *Gadget) Type() gadgets.GadgetType {
	return gadgets.TypeTraceIntervals
}

func (g *Gadget) Description() string {
	return "Gather information about running processes"
}

func (g *Gadget) Params() params.Params {
	return params.Params{
		{
			Key:          "threads",
			Title:        "Show all threads",
			Alias:        "", // TODO: was t, clashes with timeout
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          "parent-pids",
			Title:        "Show parent PIDs",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *Gadget) Columns() columnhelpers.Columns {
	return columnhelpers.NewColumnHelpers[types.Event](types.GetColumns())
}

func (g *Gadget) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.RegisterGadget(&Gadget{})
}
