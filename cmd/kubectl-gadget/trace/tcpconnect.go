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

package trace

import (
	"fmt"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcpconnect/types"

	"github.com/spf13/cobra"
)

type TcpconnectParser struct {
	BaseTraceParser
}

func newTcpconnectCmd() *cobra.Command {
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
				"comm",
				"ip",
				"saddr",
				"daddr",
				"dport",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "tcpconnect",
		Short: "Trace connect system calls",
		RunE: func(cmd *cobra.Command, args []string) error {
			tcpconnectGadget := &TraceGadget[types.Event]{
				name:        "tcpconnect",
				commonFlags: commonFlags,
				parser:      NewTcpconnectParser(&commonFlags.OutputConfig),
			}

			return tcpconnectGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewTcpconnectParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -16,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"ip":        -3,
		"saddr":     -16,
		"daddr":     -16,
		"dport":     -7,
	}

	return &TcpconnectParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func (p *TcpconnectParser) TransformEvent(event *types.Event, requestedColumns []string) string {
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
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Comm))
		case "ip":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.IPVersion))
		case "saddr":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Saddr))
		case "daddr":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Daddr))
		case "dport":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Dport))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
