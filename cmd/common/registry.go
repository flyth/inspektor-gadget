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

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/legacy"
	"github.com/inspektor-gadget/inspektor-gadget/internal/enrichers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	gadgetrunner "github.com/inspektor-gadget/inspektor-gadget/internal/gadget-runner"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"

	// Blank imports to make the gadget register itself with the registry
	// TODO: There should be a pkg allgadgets or something like it
	_ "github.com/inspektor-gadget/inspektor-gadget/internal/enrichers/localmanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/tracer"
)

func AddCommandsFromRegistry(rootCmd *cobra.Command) {
	runtime := runtime.GetRuntime()
	if runtime == nil {
		panic("no runtime set")
	}

	runtimeParams := runtime.Params()

	// Build lookup
	lookup := make(map[string]*cobra.Command)
	for _, cmd := range rootCmd.Commands() {
		lookup[cmd.Name()] = cmd
	}

	enrichersParamCollection := enrichers.EnrichersParamCollection()

	// Add all known gadgets to cobra in their respective categories
	for _, gadget := range gadgetregistry.GetGadgets() {
		if cmd, ok := lookup[gadget.Category()]; ok {
			cmd.AddCommand(buildCommandFromGadget(gadget, runtimeParams, enrichersParamCollection))
		}
	}

	// Add runtime flags
	for _, p := range runtimeParams {
		if p.Alias != "" {
			rootCmd.PersistentFlags().VarP(p, p.Key, p.Alias, p.Description)
		} else {
			rootCmd.PersistentFlags().Var(p, p.Key, p.Description)
		}
	}

	// Add enricher flags
	for _, enricherParams := range enrichersParamCollection {
		for _, p := range enricherParams {
			if p.Alias != "" {
				rootCmd.PersistentFlags().VarP(p, p.Key, p.Alias, p.Description)
			} else {
				rootCmd.PersistentFlags().Var(p, p.Key, p.Description)
			}
		}
	}
}

func buildGadgetDoc(gadget gadgets.Gadget) string {
	var out strings.Builder
	out.WriteString(gadget.Description() + "\n\n")

	if columns := gadget.Columns(); columns != nil {
		out.WriteString("Available columns:\n")
		for columnName, description := range gadget.Columns().GetColumnNamesAndDescription() {
			out.WriteString("      " + columnName + "\n")
			if description != "" {
				out.WriteString("            " + description + "\n")
			}
		}
	}
	return out.String()
}

func buildCommandFromGadget(gadget gadgets.Gadget, runtimeParams params.Params, enrichersParamCollection params.ParamsCollection) *cobra.Command {
	var outputMode string
	var verbose bool
	var showColumns []string
	var filters []string
	var sortBy []string

	// Instantiate columns - this is important to do, because we might apply filters and such to this instance
	columns := gadget.Columns()

	// Instantiate params - this is important, because the params get filled out by cobra
	params := gadget.Params()

	// Get enricher params
	validEnrichers := enrichers.GetEnrichersForGadget(gadget)
	enricherPerGadgetParamCollection := validEnrichers.PerGadgetParamCollection()

	cmd := &cobra.Command{
		Use:   gadget.Name(),
		Short: gadget.Description(),
		Long:  buildGadgetDoc(gadget),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate fields... (check for mandatory etc.)
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
			return params.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			runtime := runtime.GetRuntime()
			if runtime == nil {
				panic("no runtime set")
			}

			// init/deinit runtime
			err := runtime.Init(runtimeParams)
			if err != nil {
				return fmt.Errorf("init runtime: %w", err)
			}
			defer runtime.DeInit()

			// Let's also add some custom params like filters
			if len(filters) > 0 {
				err = columns.SetFilters(filters)
				if err != nil {
					return err // TODO: Wrap
				}
				params.AddParam("columns_filters", strings.Join(filters, ",")) // TODO: maybe encode?! difficult for CRs though
			}

			if gadget.Type().CanSort() {
				err := columns.SetSorting(sortBy)
				if err != nil {
					return err // TODO: Wrap
				}
				params.AddParam("columns_sort", strings.Join(filters, ",")) // TODO: maybe encode?! difficult for CRs though
			}

			formatter := columns.GetTextColumnsFormatter()

			// TODO: This must be handled somewhere else
			if outputMode != utils.OutputModeJSON {
				// fmt.Println(formatter.FormatHeader())
			}

			// Create a new context that will be cancelled on signal
			fe := legacy.NewFrontend()
			defer fe.Close()

			// Create new runner
			runner := gadgetrunner.NewGadgetRunner(
				fe.GetContext(),
				runtime,
				gadget,
				columns,
				logger.DefaultLogger(),
			)

			// Print errors to Stderr
			runner.Columns().SetErrorCallback(fe.Error)

			// Wire up callbacks before handing over to runtime depending on the output mode
			switch outputMode {
			default:
				formatter.SetEventCallback(fe.Output)
				runner.Columns().SetEventCallback(formatter.EventHandlerFunc())
				runner.Columns().SetEventCallbackArray(formatter.EventHandlerFuncArray())
			case utils.OutputModeJSON:
				runner.Columns().SetEventCallback(func(ev any) {
					d, _ := json.Marshal(ev)
					fmt.Fprintln(os.Stdout, string(d))
				})
				runner.Columns().SetEventCallbackArray(func(ev any) {
					d, _ := json.Marshal(ev)
					fmt.Fprintln(os.Stdout, string(d))
				})
			}

			// Finally, hand over to runtime
			return runner.RunGadget(runtimeParams, enrichersParamCollection, enricherPerGadgetParamCollection, params)
		},
	}

	// Add output flags
	if columns != nil {
		cmd.PersistentFlags().StringVarP(
			&outputMode,
			"output",
			"o",
			utils.OutputModeColumns,
			fmt.Sprintf("Output format (%s).", strings.Join(utils.SupportedOutputModes, ", ")),
		)
		cmd.PersistentFlags().BoolVarP(
			&verbose,
			"verbose", "v",
			false,
			"Print debug information",
		)
		cmd.PersistentFlags().StringSliceVarP(
			&showColumns,
			"columns", "C",
			gadget.Columns().GetDefaultColumns(),
			"Columns to output",
		)
		cmd.PersistentFlags().StringSliceVarP(
			&filters,
			"filter", "f",
			[]string{},
			"Filter rules",
		)

		// Sort is only available if we have all data available or dump output at specific intervals, so
		// make sure the gadget supports it
		if gadget.Type().CanSort() {
			cmd.PersistentFlags().StringSliceVarP(
				&sortBy,
				"sort", "s",
				[]string{}, // TODO: get initial values
				"Sort by",
			)
		}
	}

	// Add flags
	for _, p := range params {
		if p.Alias != "" {
			cmd.PersistentFlags().VarP(p, p.Key, p.Alias, p.Description)
		} else {
			cmd.PersistentFlags().Var(p, p.Key, p.Description)
		}
	}

	// Add enricher flags
	for _, enricherParams := range enricherPerGadgetParamCollection {
		for _, p := range enricherParams {
			if p.Alias != "" {
				cmd.PersistentFlags().VarP(p, p.Key, p.Alias, p.Description)
			} else {
				cmd.PersistentFlags().Var(p, p.Key, p.Description)
			}
		}
	}
	return cmd
}
