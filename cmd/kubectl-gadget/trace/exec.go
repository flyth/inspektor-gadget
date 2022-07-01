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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop/types"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"google.golang.org/grpc"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/spf13/cobra"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var execsnoopCmd = &cobra.Command{
	Use:   "exec",
	Short: "Trace new processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomExecsnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-16s %-6s %-6s %3s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PCOMM", "PID", "PPID", "RET", "ARGS")
		}

		err := genericStreams(execsnoopTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(execsnoopCmd)
	utils.AddCommonFlags(execsnoopCmd, &params)
}

// execsnoopTransformLine is called to transform an event to columns
// format according to the parameters
func execsnoopTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(e.Event, params.Verbose)
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-16s %-6d %-6d %3d",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Comm, e.Pid, e.Ppid, e.Retval))

		for _, arg := range e.Args {
			sb.WriteString(" " + arg)
		}
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%-16s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%-16s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%-16s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%-16s", e.Container))
			case "pcomm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "ppid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Ppid))
			case "ret":
				sb.WriteString(fmt.Sprintf("%-3d", e.Retval))
			case "args":
				for _, arg := range e.Args {
					sb.WriteString(fmt.Sprintf("%s ", arg))
				}
			}
			sb.WriteRune(' ')
		}
	case utils.OutputModeJSON:
		return line
	}

	return sb.String()
}

func getCustomExecsnoopColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", "CONTAINER"))
		case "pcomm":
			sb.WriteString(fmt.Sprintf("%-16s", "PCOMM"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "ppid":
			sb.WriteString(fmt.Sprintf("%-6s", "PPID"))
		case "ret":
			sb.WriteString(fmt.Sprintf("%-3s", "RET"))
		case "args":
			sb.WriteString(fmt.Sprintf("%-24s", "ARGS"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func genericStreams(transform func(line string) string) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return utils.WrapInErrSetupK8sClient(err)
	}

	podsByNode := map[string]string{}

	pods, err := client.CoreV1().Pods("gadget").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		podsByNode[pod.Spec.NodeName] = pod.Name

		namespace := "foo"
		name := "foo"
		traceID := fmt.Sprintf("trace_%s_%s", namespace, name)

		go func() {
			err := getTraceStream(pod.Name, traceID, transform)
			if err != nil {
				fmt.Printf("error was %s\n", err)
			}
		}()

	}

	<-sigs

	return nil
}

func getTraceStream(
	podname string,
	traceID string,
	transform func(line string) string,
) error {
	// setup port forwarding
	stopCh := make(chan struct{}, 1)
	readyCh := make(chan struct{})

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward",
		"gadget", podname)
	hostIP := strings.TrimLeft(config.Host, "https:/")

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return fmt.Errorf("failed to create rount tripper: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost,
		&url.URL{Scheme: "https", Path: path, Host: hostIP})
	fw, err := portforward.New(dialer, []string{"0:7500"}, stopCh, readyCh, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create port forwarding: %w", err)
	}

	defer close(stopCh)

	go func() {
		fw.ForwardPorts()
	}()

	<-readyCh

	ports, err := fw.GetPorts()
	if err != nil {
		return fmt.Errorf("failed to get ports: %w", err)
	}

	if len(ports) != 1 {
		return fmt.Errorf("one port expected. Found %d", len(ports))
	}

	// run grpc
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", ports[0].Local), grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("fail to dial: %w", err)
	}
	defer conn.Close()
	client := pb.NewGadgetTracerManagerClient(conn)

	stream, err := client.StreamGadget(context.Background(), &pb.AddTracerRequest{
		Id:       traceID,
		Selector: &pb.ContainerSelector{},
	})
	if err != nil {
		return fmt.Errorf("failed to receive stream: %w", err)
	}

	for {
		line, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading stream: %w", err)
		}

		fmt.Println(transform(line.Line))
		//fmt.Println(line.Line)
	}

	return nil
}
