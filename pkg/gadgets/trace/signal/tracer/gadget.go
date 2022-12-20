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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Gadget struct{}

func (g *Gadget) Name() string {
	return "signal"
}

func (g *Gadget) Category() string {
	return gadgets.CategoryTrace
}

func (g *Gadget) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *Gadget) Description() string {
	return "Trace signals received by processes"
}

const (
	ParamPID          = "pid"
	ParamTargetSignal = "signal"
	ParamFailedOnly   = "failed-only"
)

func (g *Gadget) Params() params.Params {
	return params.Params{
		{
			Key:          ParamPID,
			Alias:        "",
			DefaultValue: "0",
			Description:  "Show only signal sent by this particular PID",
			IsMandatory:  false,
			Tags:         nil,
			Validator:    params.ValidateNumber,
		},
		{
			Key:          ParamTargetSignal,
			Alias:        "",
			DefaultValue: "",
			Description:  `Trace only this signal (it can be an int like 9 or string beginning with "SIG" like "SIGKILL")`,
			IsMandatory:  false,
			Tags:         nil,
			Validator:    params.ValidateSlice(params.ValidateNumberRange(1, 65535)),
		},
		{
			Key:          ParamFailedOnly,
			Alias:        "",
			DefaultValue: "false",
			Description:  "Show only events where the syscall sending a signal failed",
			IsMandatory:  false,
			Tags:         nil,
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
