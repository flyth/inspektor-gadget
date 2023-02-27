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

package gadgets

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetInfo struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	Category           string                `json:"category"`
	Type               GadgetType            `json:"type"`
	Description        string                `json:"description"`
	Params             params.ParamDescs     `json:"params"`
	EventPrototype     any                   `json:"evPrototype"`
	ColumnsDefinition  any                   `json:"columnsDefinition"`
	OperatorParamDescs params.DescCollection `json:"operatorParamsDescs"`
}

// ToDesc converts a GadgetInfo into a GadgetDesc
func (g *GadgetInfo) ToDesc() GadgetDesc {
	return &gadgetDummyDesc{info: g}
}

type gadgetDummyDesc struct {
	info *GadgetInfo
}

func (g *gadgetDummyDesc) Name() string {
	return g.info.Name
}

func (g *gadgetDummyDesc) Description() string {
	return g.info.Description
}

func (g *gadgetDummyDesc) Category() string {
	return g.info.Category
}

func (g *gadgetDummyDesc) Type() GadgetType {
	return g.info.Type
}

func (g *gadgetDummyDesc) ParamDescs() params.ParamDescs {
	return g.info.Params
}

func (g *gadgetDummyDesc) Parser() parser.Parser {
	return nil
}

func (g *gadgetDummyDesc) EventPrototype() any {
	return nil
}
