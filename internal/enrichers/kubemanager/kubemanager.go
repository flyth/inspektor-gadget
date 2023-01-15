// Copyright 2022-2023 The Inspektor Gadget authors
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

package kubemanager

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/enrichers"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	NodeName            = "node-name"
	HookMode            = "hook-mode"
	FallbackPodInformer = "fallback-podinformer"

	ContainerName = "containername"
	PodName       = "podname"
	Node          = "node"
	Selector      = "selector"
	AllNamespaces = "all-namespaces"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type ContainersMapSetter interface {
	SetContainersMap(*ebpf.Map)
}

type Attacher interface {
	AttachGeneric(container *containercollection.Container, handler any) error
	DetachGeneric(*containercollection.Container) error
}

type KubeManager struct {
	gadgetManager *gadgettracermanager.GadgetTracerManager
	rc            []*containerutils.RuntimeConfig
}

func (l *KubeManager) Name() string {
	return "KubeManager"
}

func (l *KubeManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers in a Kubernetes context"
}

func (l *KubeManager) Dependencies() []string {
	return nil
}

func (l *KubeManager) Params() params.Params {
	return params.Params{
		{
			Key:          NodeName,
			Alias:        "",
			DefaultValue: "",
			Description:  "Name of the node this is running on",
			IsMandatory:  true,
		},
		{
			Key:          HookMode,
			Alias:        "",
			DefaultValue: "auto",
			Description:  "Name of the node this is running on",
			IsMandatory:  true,
			PossibleValues: []string{
				"auto",
				"crio",
				"podinformer",
				"nri",
				"fanotify",
			},
		},
		{
			Key:          FallbackPodInformer,
			Alias:        "",
			DefaultValue: "true",
			Description:  "use pod informer as a fallback for the main hook",
			TypeHint:     params.TypeBool,
			IsMandatory:  true,
		},
	}
}

func (l *KubeManager) PerGadgetParams() params.Params {
	return params.Params{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
		},
		{
			Key:         PodName,
			Alias:       "p",
			Description: "Show only data from pods with that name",
		},
		{
			Key:         Selector,
			Alias:       "l",
			Description: "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
		},
		// TODO: Namespaces?
		{
			Key:          AllNamespaces,
			Alias:        "A",
			DefaultValue: "false",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *KubeManager) CanEnrich(gadget gadgets.Gadget) bool {
	// We need to be able to get MountNSID and set ContainerInfo, so check for that first
	_, canEnrichEvent := gadget.EventPrototype().(enrichers.KubernetesFromMountNSID)

	// Secondly, we need to be able to inject the ebpf map onto the tracer
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		log.Printf("cannot instantiate")
		return false
	}

	instance, err := gi.NewInstance(nil)
	if err != nil {
		log.Printf("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)
	_, isContainersMapSetter := instance.(ContainersMapSetter)

	log.Printf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Printf("> isAttacher: %v", isAttacher)
	log.Printf("> isContainersMapSetter: %v", isContainersMapSetter)

	return (isMountNsMapSetter && canEnrichEvent) || isAttacher || isContainersMapSetter
}

func (l *KubeManager) Init(enricherParams params.Params) error {
	rp := params.ParamMapFromParams(enricherParams)

	conf := &gadgettracermanager.Conf{
		NodeName: rp[NodeName].String(),
		HookMode: rp[HookMode].String(),
	}
	params.ParamAsBool(rp[FallbackPodInformer], &conf.FallbackPodInformer)

	// TODO: fill config
	gadgetManager, err := gadgettracermanager.NewServer(conf)
	if err != nil {
		return err
	}
	l.gadgetManager = gadgetManager

	return nil
}

func (l *KubeManager) Cleanup() error {
	l.gadgetManager.Close()
	return nil
}

type KubeManagerTrace struct {
	*KubeManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
}

func (l *KubeManager) PreGadgetRun(runner enrichers.Runner, tracer any, perGadgetParams params.Params) (enrichers.Enricher, error) {
	_, canEnrichEvent := runner.Gadget().EventPrototype().(enrichers.KubernetesFromMountNSID)

	log := runner.Logger()

	traceInstance := &KubeManagerTrace{
		KubeManager:        l,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
	}

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Name:    perGadgetParams.Get(ContainerName),
		Podname: perGadgetParams.Get(PodName),
		// TODO: Namespace + Labels
	}

	if setter, ok := tracer.(MountNsMapSetter); ok {
		// Create mount namespace map to filter by containers
		mountnsmap, err := l.gadgetManager.TracerMountNsMap(runner.ID())
		if err != nil {
			return nil, commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		traceInstance.mountnsmap = mountnsmap
	}

	if setter, ok := tracer.(ContainersMapSetter); ok {
		setter.SetContainersMap(l.gadgetManager.ContainersMap())
	}

	if attacher, ok := tracer.(Attacher); ok {
		traceInstance.attacher = attacher

		attachContainerFunc := func(container *containercollection.Container) {
			var cbFunc any

			if runner.Columns() != nil {
				cbFunc = runner.Columns().EventHandlerFunc(runner.Enrichers().Enrich, func(a any) {
					if !container.HostNetwork {
						s := a.(enrichers.ContainerInfoSetters)
						s.SetContainerInfo(container.Podname, container.Namespace, container.Name)
					}
				})
			}

			log.Debugf("calling gadget.AttachGeneric()")
			err := attacher.AttachGeneric(container, cbFunc)
			if err != nil {
				// TODO: return oob
				// msg := fmt.Sprintf("start tracing container %q: %s", container.Name, err)
				// eventCallback(container, base(eventtypes.Err(msg)))
				log.Warnf("attach: %v", err)
				return
			}

			traceInstance.attachedContainers[container] = struct{}{}

			// TODO: return oob
			log.Debugf("tracer attached")
			// eventCallback(container, base(eventtypes.Debug("tracer attached")))
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			err := attacher.DetachGeneric(container)
			if err != nil {
				// TODO: return oob
				// msg := fmt.Sprintf("stop tracing container %q: %s", container.Name, err)
				// eventCallback(container, base(eventtypes.Err(msg)))
				log.Warnf("detach: %v", err)
				return
			}
			// TODO: return oob
			log.Debugf("tracer detached")
			// eventCallback(container, base(eventtypes.Debug("tracer detached")))
		}

		id := uuid.New()
		traceInstance.subscriptionKey = id.String()

		log.Debugf("add subscription")
		containers := l.gadgetManager.Subscribe(
			traceInstance.subscriptionKey,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				switch event.Type {
				case containercollection.EventTypeAddContainer:
					attachContainerFunc(event.Container)
				case containercollection.EventTypeRemoveContainer:
					detachContainerFunc(event.Container)
				}
			},
		)

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}

	return traceInstance, nil
}

func (l *KubeManagerTrace) PostGadgetRun() error {
	l.KubeManager.PostGadgetRun()

	if l.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		// l.gadgetManager.RemoveMountNsMap() // TODO: Check
	}
	if l.subscriptionKey != "" {
		log.Debugf("calling Unsubscribe()")
		l.gadgetManager.Unsubscribe(l.subscriptionKey)

		// emit detach for all remaining containers
		for container := range l.attachedContainers {
			l.attacher.DetachGeneric(container)
		}
	}
	return nil
}

func (l *KubeManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}

	event, ok := ev.(enrichers.KubernetesFromMountNSID)
	if !ok {
		return errors.New("invalid event to enrich")
	}
	l.gadgetManager.ContainerCollection.EnrichEvent(event)

	container := l.gadgetManager.ContainerCollection.LookupContainerByMntns(event.GetMountNSID())
	if container != nil {
		event.SetContainerInfo(container.Podname, container.Namespace, container.Name)
	}
	return nil
}

func (l *KubeManager) PostGadgetRun() error {
	return nil
}

func (l *KubeManager) EnrichEvent(a any) error {
	return nil
}

func init() {
	enrichers.RegisterEnricher(&KubeManager{})
}
