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

package local

import (
	"errors"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runtime struct {
	rc []*containerutils.RuntimeConfig
}

func (r *Runtime) Init(runtimeParams params.Params) error {
	return nil
}

func (r *Runtime) DeInit() error {
	return nil
}

func (r *Runtime) RunGadget(runner runtime.Runner, runtimeParams params.Params,
	enricherPerGadgetParamCollection params.ParamsCollection,
	gadgetParams params.Params,
) error {
	runner.Logger().Debugf("running with local runtime")

	gadgetInst, ok := runner.Gadget().(gadgets.GadgetInstantiate)
	if !ok {
		return errors.New("gadget not instantiable")
	}

	runner.Logger().Debugf("> Params: %+v", runtimeParams.ParamMap())

	switch runner.Gadget().Type() {
	case gadgets.TypeTrace,
		gadgets.TypeTracePerContainer,
		gadgets.TypeTraceIntervals,
		gadgets.TypeProfile,
		gadgets.TypeOneShot:
		return r.RunTraceGadget(runner, gadgetInst, enricherPerGadgetParamCollection, gadgetParams)
	default:
		return fmt.Errorf("unimplemented gadget type: %s", runner.Gadget().Type())
	}

	return nil
}

func (r *Runtime) Params() params.Params {
	return nil
}
