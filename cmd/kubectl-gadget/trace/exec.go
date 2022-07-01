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

package trace

import (
	"fmt"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/types"

	"github.com/spf13/cobra"
)

type ExecParser struct {
	BaseTraceParser
}

func newExecCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: utils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"pid",
				"ppid",
				"pcomm",
				"ret",
				"args",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "exec",
		Short: "Trace new processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			execGadget := &TraceGadget[types.Event]{
				name:        "execsnoop",
				commonFlags: commonFlags,
				parser:      NewExecParser(&commonFlags.OutputConfig),
			}

			return execGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewExecParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -16,
		"container": -16,
		"pid":       -7,
		"ppid":      -7,
		"pcomm":     -16,
		"ret":       -4,
		"args":      -24,
	}

	return &ExecParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func (p *ExecParser) TransformEvent(event *types.Event, requestedColumns []string) string {
	var sb strings.Builder

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Pid))
		case "ppid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Ppid))
		case "pcomm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Comm))
		case "ret":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Retval))
		case "args":
			for _, arg := range event.Args {
				sb.WriteString(fmt.Sprintf("%s ", arg))
			}
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
