// Copyright 2024 The Inspektor Gadget authors
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

package common

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func NewRunCommand(rootCmd *cobra.Command, runtime runtime.Runtime, hiddenColumnTags []string) *cobra.Command {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()

	runtimeParams := runtime.ParamDescs().ToParams()

	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()

	// Add operator global flags
	operatorsGlobalParamsCollection := operators.GlobalParamsCollection()

	// gadget parameters are only available after contacting the server
	gadgetParams := make(params.Params, 0)

	var info *api.GadgetInfo
	paramLookup := map[string]*params.Param{}

	cmd := &cobra.Command{
		Use:          "run",
		Short:        "Run gadgets",
		SilenceUsage: true, // do not print usage when there is an error
		// We have to disable flag parsing in here to be able to handle certain
		// flags more dynamically and have `--help` also react to those changes.
		// Instead, we need to manually
		// * call cmd.ParseFlags()
		// * handle `--help` after changing the params dynamically
		// * handle everything that could have been handled inside
		//   `PersistentPreRun(E)` of a parent cmd, as the flags wouldn't have
		//   been parsed there (e.g. --verbose)
		DisableFlagParsing: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := runtime.Init(runtimeGlobalParams)
			if err != nil {
				return fmt.Errorf("initializing runtime: %w", err)
			}
			defer runtime.Close()

			// we need to re-enable flag parsing, as utils.ParseEarlyFlags() would
			// not do anything otherwise
			cmd.DisableFlagParsing = false

			// Parse flags that are known at this time, like the ones we get from the gadget descriptor
			if err := utils.ParseEarlyFlags(cmd, args); err != nil {
				return err
			}

			// Before running the gadget, we need to get the gadget info to perform
			// different tasks like creating the parser and setting flags for the
			// gadget's parameters.
			actualArgs := cmd.Flags().Args()
			if len(actualArgs) == 0 {
				return cmd.ParseFlags(args)
			}

			ops := make([]operators.DataOperator, 0)
			for _, op := range operators.GetDataOperators() {
				ops = append(ops, op)
			}
			ops = append(ops, clioperator.CLIOperator)

			gadgetCtx := gadgetcontext.NewOCI(
				context.Background(),
				actualArgs[0], // imageName
				gadgetcontext.WithDataOperators(ops...),
			)

			// GetOCIGadget needs at least the params from the oci handler, so let's prepare those in here
			paramValueMap := make(map[string]string)
			ociParams.CopyToMap(paramValueMap, "operator.oci.")

			// Fetch gadget information; TODO: this can potentially be cached
			info, err = runtime.GetOCIGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
			if err != nil {
				return fmt.Errorf("fetching gadget information: %w", err)
			}

			for _, p := range info.Params {
				// Skip already registered params (but this still lets "operator.oci.ebpf." pass)
				if p.Prefix == "operator.oci." {
					continue
				}
				param := apihelpers.ParamToParamDesc(p).ToParam()
				paramLookup[p.Prefix+p.Key] = param
				gadgetParams.Add(param)
			}

			AddFlags(cmd, &gadgetParams, nil, runtime)

			return cmd.ParseFlags(args)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// args from RunE still contains all flags, since we manually parsed them,
			// so we need to manually pull the remaining args here
			args := cmd.Flags().Args()

			showHelp, _ := cmd.Flags().GetBool("help")

			if len(args) == 0 {
				if showHelp {
					additionalMessage := "Specify the gadget image to get more information about it"
					cmd.Long = fmt.Sprintf("%s\n\n%s", cmd.Short, additionalMessage)
				}
				return cmd.Help()
			}

			if showHelp {
				return cmd.Help()
			}

			// we also manually need to check the verbose flag, as PersistentPreRunE in
			// verbose.go will not have the correct information due to manually parsing
			// the flags
			checkVerboseFlag()

			fe := console.NewFrontend()
			defer fe.Close()

			ctx := fe.GetContext()

			ops := make([]operators.DataOperator, 0)
			for _, op := range operators.GetDataOperators() {
				ops = append(ops, op)
			}
			ops = append(ops, clioperator.CLIOperator)

			gadgetCtx := gadgetcontext.NewOCI(
				ctx,
				args[0],
				gadgetcontext.WithDataOperators(ops...),
			)

			paramValueMap := make(map[string]string)

			// Write back param values
			for _, p := range info.Params {
				paramValueMap[p.Prefix+p.Key] = paramLookup[p.Prefix+p.Key].String()
			}

			// Also copy special oci params
			ociParams.CopyToMap(paramValueMap, "operator.oci.")

			err := runtime.RunOCIGadget(gadgetCtx, runtimeParams, paramValueMap)
			if err != nil {
				return err
			}
			return nil
		},
	}

	AddFlags(cmd, ociParams, nil, runtime)
	AddFlags(cmd, runtimeGlobalParams, nil, runtime)
	AddFlags(cmd, runtimeParams, nil, runtime)

	for _, operatorParams := range operatorsGlobalParamsCollection {
		AddFlags(cmd, operatorParams, nil, runtime)
	}

	return cmd
}
