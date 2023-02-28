// Copyright 2023 The Inspektor Gadget authors
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

package grpcruntime

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	clientset "github.com/inspektor-gadget/inspektor-gadget/pkg/client/clientset/versioned"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func (r *Runtime) deployCRs(gadgetCtx runtime.GadgetContext, pods []v1.Pod) error {
	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to creating RESTConfig: %w", err)
	}

	client, err := clientset.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to set up trace client: %w", err)
	}

	for _, pod := range pods {
		gadgetCtx.Logger().Debugf("deploying CR for node %q", pod.Spec.NodeName)
		err := r.deployCR(gadgetCtx, client, pod)
		if err != nil {
			gadgetCtx.Logger().Errorf("node %q: %w", pod.Spec.NodeName, err)
		}
	}

	return nil
}

func (r *Runtime) deployCR(gadgetCtx runtime.GadgetContext, client *clientset.Clientset, pod v1.Pod) error {
	traceID := uuid.New()

	allParams := make(map[string]string)
	gadgetCtx.GadgetParams().CopyToMap(allParams, "")
	gadgetCtx.OperatorsParamCollection().CopyToMap(allParams, "operator.")

	trace := &gadgetv1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: gadgetCtx.GadgetDesc().Name() + "-",
			Namespace:    "gadget",
			Annotations:  map[string]string{
				// utils.GadgetOperation: "none",
			},
			Labels: map[string]string{
				utils.GlobalTraceID: traceID.String(),
				// Add all this information here to be able to find the trace thanks
				// to them when calling getTraceListFromParameters().
				"gadgetName":     gadgetCtx.GadgetDesc().Name(),
				"gadgetCategory": gadgetCtx.GadgetDesc().Category(),
				"nodeName":       pod.Spec.NodeName,
				// Kubernetes labels cannot contain ',' but can contain '_'
				// Kubernetes names cannot contain either, so no need for more complicated escaping
				// "namespace":     strings.Replace(config.CommonFlags.Namespace, ",", "_", -1),
				// "podName":       config.CommonFlags.Podname,
				// "containerName": config.CommonFlags.Containername,
				// "outputMode":    string(config.TraceOutputMode), // unused for now
				// We will not add config.TraceOutput as label because it can contain
				// "/" which is forbidden in labels.
			},
		},
		Spec: gadgetv1alpha1.TraceSpec{
			Node:    pod.Spec.NodeName,
			Gadget:  gadgetCtx.GadgetDesc().Name(),
			RunMode: gadgetv1alpha1.RunModeAuto,
			// Filter:  filter, // Unused for now
			// OutputMode: config.TraceOutputMode, // Unused
			// Output:     config.TraceOutput, // Unused
			Parameters: allParams,
		},
	}

	_, err := client.GadgetV1alpha1().Traces("gadget").Create(
		context.TODO(), trace, metav1.CreateOptions{},
	)

	return err
}
