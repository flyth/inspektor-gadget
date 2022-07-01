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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/oomkill/types"
	"github.com/spf13/cobra"
)

type OOMKillParser struct {
	BaseTraceParser
}

func newOOMKillCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: utils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"kpid",
				"kcomm",
				"pages",
				"tpid",
				"tcomm",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "oomkill",
		Short: "Trace when OOM killer is triggered and kills a process",
		RunE: func(cmd *cobra.Command, args []string) error {
			oomkillGadget := &TraceGadget[types.Event]{
				name:        "oomkill",
				commonFlags: commonFlags,
				parser:      NewOOMKillParser(&commonFlags.OutputConfig),
			}

			return oomkillGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewOOMKillParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -16,
		"container": -16,
		"kpid":      -7,
		"kcomm":     -16,
		"pages":     -6,
		"tpid":      -7,
		"tcomm":     -16,
	}

	return &OOMKillParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func (p *OOMKillParser) TransformEvent(event *types.Event, requestedColumns []string) string {
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
		case "kpid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.KilledPid))
		case "kcomm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.KilledComm))
		case "pages":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Pages))
		case "tpid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.TriggeredPid))
		case "tcomm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.TriggeredComm))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
