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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/legacy"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/enrichers"
	gadgetrunner "github.com/inspektor-gadget/inspektor-gadget/internal/gadget-runner"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	cols "github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
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

func AddCommandsFromRegistry(rootCmd *cobra.Command, runtime runtime.Runtime, columnFilters []cols.ColumnFilter) {
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
			cmd.AddCommand(buildCommandFromGadget(gadget, columnFilters, runtime, runtimeParams, enrichersParamCollection))
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

	// Add enricher global flags
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

func buildGadgetDoc(gadget gadgets.Gadget, columns columnhelpers.Columns) string {
	var out strings.Builder
	out.WriteString(gadget.Description() + "\n\n")

	if columns != nil {
		out.WriteString("Available columns:\n")
		for columnName, description := range columns.GetColumnNamesAndDescription() {
			out.WriteString("      " + columnName + "\n")
			if description != "" {
				out.WriteString("            " + description + "\n")
			}
		}
	}
	return out.String()
}

func buildCommandFromGadget(gadget gadgets.Gadget, columnFilters []cols.ColumnFilter, runtime runtime.Runtime, runtimeParams params.Params, enrichersParamCollection params.ParamsCollection) *cobra.Command {
	var outputMode string
	var verbose bool
	var showColumns []string
	var filters []string
	var timeout int

	outputFormats := gadgets.OutputFormats{}
	defaultOutputFormat := ""

	// Instantiate columns - this is important to do, because we might apply filters and such to this instance
	columns := gadget.Columns()
	if columns != nil && columnFilters != nil {
		columns.SetColumnFilters(columnFilters...)
	}

	// Instantiate params - this is important, because the params get filled out by cobra
	params := gadget.Params()

	// Get per gadget enricher params
	validEnrichers := enrichers.GetEnrichersForGadget(gadget)
	enricherPerGadgetParamCollection := validEnrichers.PerGadgetParamCollection()

	cmd := &cobra.Command{
		Use:   gadget.Name(),
		Short: gadget.Description(),
		Long:  buildGadgetDoc(gadget, columns),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
			// Validate flags
			if err := enricherPerGadgetParamCollection.Validate(); err != nil {
				return err
			}
			return params.Validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runtime.Init(runtimeParams)
			if err != nil {
				return fmt.Errorf("init runtime: %w", err)
			}
			defer runtime.DeInit()

			fe := legacy.NewFrontend()
			defer fe.Close()

			var ctx context.Context
			ctx = fe.GetContext()

			if timeout != 0 {
				tmpCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
				ctx = tmpCtx
			}

			// Create new runner
			runner := gadgetrunner.NewGadgetRunner(
				ctx,
				"",
				runtime,
				gadget,
				columns,
				logger.DefaultLogger(),
			)

			if columns != nil {
				// Add some custom params like filters that are available when using columns
				if len(filters) > 0 {
					err = columns.SetFilters(filters)
					if err != nil {
						return err // TODO: Wrap
					}
					params.AddParam("columns_filters", strings.Join(filters, ",")) // TODO: maybe encode?! difficult for CRs though
				}

				if gadget.Type().CanSort() {
					err := columns.SetSorting(strings.Split(params.Get(gadgets.ParamSortBy), ","))
					if err != nil {
						return err // TODO: Wrap
					}
				}

				// Print errors to Stderr
				formatter := columns.GetTextColumnsFormatter()
				formatter.SetShowColumns(showColumns)
				runner.Columns().SetErrorCallback(fe.Error)

				// TODO: This must be handled somewhere else
				if outputMode != utils.OutputModeJSON {
					fmt.Println(formatter.FormatHeader())
				}

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
			} else {
				defer func() {
					res, _ := runner.GetResult()
					transformer := gadget.(gadgets.GadgetOutputFormats)
					formats, defaultFormat := transformer.OutputFormats()
					transformed, _ := formats[defaultFormat].Transform(res)
					fmt.Fprint(os.Stdout, string(transformed))
				}()
			}

			// Finally, hand over to runtime
			return runner.RunGadget(runtimeParams, enrichersParamCollection, enricherPerGadgetParamCollection, params)
		},
	}

	if gadget.Type() != gadgets.TypeOneShot {
		// Add timeout
		cmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 0, "Number of seconds that the gadget will run for, 0 to disable")
	}

	cmd.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)

	outputFormats.Append(gadgets.OutputFormats{
		"json": {
			Name:        "JSON",
			Description: "The output of the gadget is returned as raw JSON",
			Transform:   nil,
		},
	})
	defaultOutputFormat = "json"

	// Add output flags
	if columns != nil {
		outputFormats.Append(gadgets.OutputFormats{
			"columns": {
				Name:        "Columns",
				Description: "The output of the gadget is formatted in human readable columns",
				Transform:   nil,
			},
		})
		defaultOutputFormat = "columns"

		cmd.PersistentFlags().StringSliceVarP(
			&showColumns,
			"columns", "C",
			columns.GetDefaultColumns(),
			"Columns to output",
		)
		cmd.PersistentFlags().StringSliceVarP(
			&filters,
			"filter", "F",
			[]string{},
			"Filter rules",
		)

		// Add params matching the gadget type
		params.AddParams(gadgets.GadgetParams(gadget, columns))
	}

	// Add alternative output formats available in the gadgets
	if outputFormatInterface, ok := gadget.(gadgets.GadgetOutputFormats); ok {
		formats, defaultFormat := outputFormatInterface.OutputFormats()
		outputFormats.Append(formats)
		defaultOutputFormat = defaultFormat
	}

	var supportedOutputFormats []string
	var outputFomatsHelp []string

	for ofKey, of := range outputFormats {
		supportedOutputFormats = append(supportedOutputFormats, ofKey)
		desc := fmt.Sprintf("%s (%s)", of.Name, ofKey)
		if of.Description != "" {
			desc += fmt.Sprintf("\n  %s", of.Description)
		}
		outputFomatsHelp = append(outputFomatsHelp, desc)
	}
	sort.Strings(outputFomatsHelp)
	outputFomatsHelp = append([]string{fmt.Sprintf("Output format (%s).", strings.Join(supportedOutputFormats, ", ")), ""}, outputFomatsHelp...)

	cmd.PersistentFlags().StringVarP(
		&outputMode,
		"output",
		"o",
		defaultOutputFormat,
		strings.Join(outputFomatsHelp, "\n")+"\n\n",
	)

	// Add gadget flags
	for _, p := range params {
		desc := p.Description

		if p.PossibleValues != nil {
			desc += " [" + strings.Join(p.PossibleValues, ", ") + "]"
		}

		if p.Alias != "" {
			cmd.PersistentFlags().VarP(p, p.Key, p.Alias, desc)
		} else {
			cmd.PersistentFlags().Var(p, p.Key, desc)
		}
	}

	// Add per-gadget enricher flags
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
