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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/mountsnoop/types"

	"github.com/spf13/cobra"
)

type MountParser struct {
	BaseTraceParser
}

func newMountCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: utils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"comm",
				"pid",
				"tid",
				"mnt_ns",
				"call",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "mount",
		Short: "Trace mount and umount system calls",
		RunE: func(cmd *cobra.Command, args []string) error {
			mountGadget := &TraceGadget[types.Event]{
				name:        "mountsnoop",
				commonFlags: commonFlags,
				parser:      NewMountParser(&commonFlags.OutputConfig),
			}

			return mountGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewMountParser(outputConfig *utils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -16,
		"container": -16,
		"pid":       -7,
		"tid":       -7,
		"mnt_ns":    -11,
		"comm":      -16,
		"op":        -6,
		"ret":       -4,
		"lat":       -8,
		"fs":        -16,
		"src":       -16,
		"target":    -16,
		"data":      -16,
		"call":      -16,
		"flags":     -24,
	}

	return &MountParser{
		BaseTraceParser: BaseTraceParser{
			columnsWidth: columnsWidth,
			outputConfig: outputConfig,
		},
	}
}

func getCall(e *types.Event) string {
	switch e.Operation {
	case "mount":
		format := `mount("%s", "%s", "%s", %s, "%s") = %d`
		return fmt.Sprintf(format, e.Source, e.Target, e.Fs, strings.Join(e.Flags, " | "),
			e.Data, e.Retval)
	case "umount":
		format := `umount("%s", %s) = %d`
		return fmt.Sprintf(format, e.Target, strings.Join(e.Flags, " | "), e.Retval)
	}

	return ""
}

func (p *MountParser) TransformEvent(event *types.Event, requestedColumns []string) string {
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
		case "tid":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Tid))
		case "mnt_ns":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.MountNsID))
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Comm))
		case "op":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Operation))
		case "ret":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Retval))
		case "lat":
			sb.WriteString(fmt.Sprintf("%*d", p.columnsWidth[col], event.Latency/1000))
		case "fs":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Fs))
		case "src":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Source))
		case "target":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Target))
		case "data":
			sb.WriteString(fmt.Sprintf("%*s", p.columnsWidth[col], event.Data))
		case "call":
			sb.WriteString(fmt.Sprintf("%-*s", p.columnsWidth[col], getCall(event)))
		case "flags":
			sb.WriteString(fmt.Sprintf("%s", strings.Join(event.Flags, " | ")))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
