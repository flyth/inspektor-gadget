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

package remote

import (
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runtime struct{}

var gadgetRewrites = map[string]string{
	"signal": "sigsnoop",
	"bind":   "bindsnoop",
	"ebpf":   "ebpftop",
}

func (r *Runtime) Init(runtimeParams params.Params) error {
	return nil
}

func (r *Runtime) DeInit() error {
	return nil
}

func (r *Runtime) RunGadget(runner runtime.Runner, runtimeParams params.Params, gadgetParams params.Params) error {
	cflags := &utils.CommonFlags{}

	gadgetName := runner.Gadget().Name()
	if altName, ok := gadgetRewrites[gadgetName]; ok {
		gadgetName = altName
	}

	config := &utils.TraceConfig{
		GadgetName:       gadgetName,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      cflags,
		Parameters:       gadgetParams.ParamMap(),
	}

	jsonHandler := runner.Columns().JSONHandlerFunc()

	// TODO: returning a string here should be deprecated in RunTraceAndPrintStream
	handler := func(line string) string {
		jsonHandler([]byte(line))
		return ""
	}

	if err := utils.RunTraceAndPrintStream(config, handler); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	return nil
}

func (r *Runtime) Params() params.Params {
	return params.Params{
		{
			Key:         "selector",
			Alias:       "l",
			Description: "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
		},
		{
			Key:         "node",
			Description: "Show only data from pods running in that node",
		},
		{
			Key:         "podname",
			Alias:       "p",
			Description: "Show only data from pods with that name",
		},
		{
			Key:         "containername",
			Alias:       "c",
			Description: "Show only data from containers with that name",
		},
		{
			Key:          "all-namespaces",
			Alias:        "A",
			DefaultValue: "false",
			Description:  "Show only data from containers with that name",
			Validator:    params.ValidateBool,
		},
		{
			Key:          "timeout",
			DefaultValue: "0",
			Validator:    params.ValidateNumber,
		},
	}
}

func init() {
	runtime.SetRuntime(func() runtime.Runtime { return &Runtime{} })
}
