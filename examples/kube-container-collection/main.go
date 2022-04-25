// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/types"

	"github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var (
	kubeconfig = flag.String("kubeconfig", "", "kubeconfig")
	node       = flag.String("node", "", "Node name")

	client *kubernetes.Clientset
	cc     *containercollection.ContainerCollection
)

func publishEvent(c *pb.ContainerDefinition, reason, message string) {
	eventTime := metav1.NewTime(time.Now())
	event := &api.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", c.Podname, time.Now().UnixNano()),
			Namespace: c.Namespace,
		},
		Source: api.EventSource{
			Component: "RuncHook",
			Host:      *node,
		},
		Count:               1,
		ReportingController: "github.com/kinvolk/inspektor-gadget",
		ReportingInstance:   os.Getenv("POD_NAME"), // pod name
		FirstTimestamp:      eventTime,
		LastTimestamp:       eventTime,
		InvolvedObject: api.ObjectReference{
			Kind:      "Pod",
			Namespace: c.Namespace,
			Name:      c.Podname,
			UID:       types.UID(c.PodUid),
		},
		Type:    api.EventTypeNormal,
		Reason:  reason,
		Message: message,
	}

	if _, err := client.CoreV1().Events(c.Namespace).Create(context.TODO(), event, metav1.CreateOptions{}); err != nil {
		fmt.Printf("couldn't create event: %s\n", err)
	}
}

func callback(notif pubsub.PubSubEvent) {
	switch notif.Type {
	case pubsub.EventTypeAddContainer:
		fmt.Printf("Container added: %v pid %d\n", notif.Container.Id, notif.Container.Pid)
		if notif.Container.OciConfig != "" {
			publishEvent(&notif.Container, "NewContainerConfig", notif.Container.OciConfig)
		}
	case pubsub.EventTypeRemoveContainer:
		fmt.Printf("Container removed: %v pid %d\n", notif.Container.Id, notif.Container.Pid)
	default:
		return
	}
}

func main() {
	flag.Parse()

	if *kubeconfig == "" && os.Getenv("KUBECONFIG") != "" {
		*kubeconfig = os.Getenv("KUBECONFIG")
	}

	if *node == "" && os.Getenv("NODE_NAME") != "" {
		*node = os.Getenv("NODE_NAME")
	}

	config, err := k8sutil.NewKubeConfig(*kubeconfig)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	client, err = kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	containerEventFuncs := []pubsub.FuncNotify{callback}
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(containerEventFuncs...),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithKubernetesEnrichment(*node, config),
		containercollection.WithRuncFanotify(),
	}

	cc = &containercollection.ContainerCollection{}
	err = cc.ContainerCollectionInitialize(opts...)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready\n")

	cc.ContainerRange(func(c *pb.ContainerDefinition) {
		fmt.Printf("%+v\n", c)
	})

	select {}
}
