// Copyright 2022-2023 The Inspektor Gadget authors
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

package runtime

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetContext interface {
	ID() string
	Parser() parser.Parser
	GadgetDesc() gadgets.GadgetDesc
	Context() context.Context
	Operators() operators.Operators
	Logger() logger.Logger
	RuntimeParams() *params.Params
	GadgetParams() *params.Params
	OperatorsParamCollection() params.Collection
}

type GadgetInfo struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	Category           string                `json:"category"`
	Type               string                `json:"type"`
	Description        string                `json:"description"`
	Params             params.ParamDescs     `json:"params"`
	EventPrototype     any                   `json:"evPrototype"`
	ColumnsDefinition  any                   `json:"columnsDefinition"`
	OperatorParamDescs params.DescCollection `json:"operatorParamsDescs"`
}

type OperatorInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Catalog struct {
	Gadgets   []*GadgetInfo
	Operators []*OperatorInfo
}

// Runtime is the interface for gadget runtimes like kubectl-gadget, local-gadget
// or gadgettracermgr
type Runtime interface {
	Init(*params.Params) error
	Close() error
	GlobalParamDescs() params.ParamDescs
	ParamDescs() params.ParamDescs
	RunGadget(gadgetCtx GadgetContext) ([]byte, error)
	GetCatalog() (*Catalog, error)
}
