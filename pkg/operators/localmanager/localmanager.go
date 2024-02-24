// Copyright 2022-2024 The Inspektor Gadget authors
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

package localmanager

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	igmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/ig-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	OperatorName         = "LocalManager"
	OperatorInstanceName = "LocalManagerTrace"
	Runtimes             = "runtimes"
	ContainerName        = "containername"
	Host                 = "host"
	DockerSocketPath     = "docker-socketpath"
	ContainerdSocketPath = "containerd-socketpath"
	CrioSocketPath       = "crio-socketpath"
	PodmanSocketPath     = "podman-socketpath"
	ContainerdNamespace  = "containerd-namespace"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type LocalManager struct {
	igManager *igmanager.IGManager
	rc        []*containerutilsTypes.RuntimeConfig
}

func (l *LocalManager) Name() string {
	return OperatorName
}

func (l *LocalManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers"
}

func (l *LocalManager) Dependencies() []string {
	return nil
}

func (l *LocalManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          Runtimes,
			Alias:        "r",
			DefaultValue: strings.Join(containerutils.AvailableRuntimes, ","),
			Description: fmt.Sprintf("Container runtimes to be used separated by comma. Supported values are: %s",
				strings.Join(containerutils.AvailableRuntimes, ", ")),
			// PossibleValues: containerutils.AvailableRuntimes, // TODO
		},
		{
			Key:          DockerSocketPath,
			DefaultValue: runtimeclient.DockerDefaultSocketPath,
			Description:  "Docker Engine API Unix socket path",
		},
		{
			Key:          ContainerdSocketPath,
			DefaultValue: runtimeclient.ContainerdDefaultSocketPath,
			Description:  "Containerd CRI Unix socket path",
		},
		{
			Key:          CrioSocketPath,
			DefaultValue: runtimeclient.CrioDefaultSocketPath,
			Description:  "CRI-O CRI Unix socket path",
		},
		{
			Key:          PodmanSocketPath,
			DefaultValue: runtimeclient.PodmanDefaultSocketPath,
			Description:  "Podman Unix socket path",
		},
		{
			Key:          ContainerdNamespace,
			DefaultValue: constants.K8sContainerdNamespace,
			Description:  "Containerd namespace to use",
		},
	}
}

func (l *LocalManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
		{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *LocalManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// // Workaround for new interfaces
	// if gadget.Type() == "oci" {
	// 	return true
	// }

	// We need to be able to get MountNSID or NetNSID, and set ContainerInfo, so
	// check for that first
	_, canEnrichEventFromMountNs := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadget.EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	// Secondly, we need to be able to inject the ebpf map onto the gadget instance
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Warnf("failed to create dummy %s instance: %s", OperatorName, err)
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf("\t> canEnrichEventFromMountNs: %v", canEnrichEventFromMountNs)
	log.Debugf("\t> canEnrichEventFromNetNs: %v", canEnrichEventFromNetNs)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)

	return isMountNsMapSetter || canEnrichEvent || isAttacher
}

func (l *LocalManager) Init(operatorParams *params.Params) error {
	rc := make([]*containerutilsTypes.RuntimeConfig, 0)
	parts := operatorParams.Get(Runtimes).AsStringSlice()

partsLoop:
	for _, p := range parts {
		runtimeName := types.String2RuntimeName(strings.TrimSpace(p))
		socketPath := ""
		namespace := ""

		switch runtimeName {
		case types.RuntimeNameDocker:
			socketPath = operatorParams.Get(DockerSocketPath).AsString()
		case types.RuntimeNameContainerd:
			socketPath = operatorParams.Get(ContainerdSocketPath).AsString()
			namespace = operatorParams.Get(ContainerdNamespace).AsString()
		case types.RuntimeNameCrio:
			socketPath = operatorParams.Get(CrioSocketPath).AsString()
		case types.RuntimeNamePodman:
			socketPath = operatorParams.Get(PodmanSocketPath).AsString()
		default:
			return commonutils.WrapInErrInvalidArg("--runtime / -r",
				fmt.Errorf("runtime %q is not supported", p))
		}

		for _, r := range rc {
			if r.Name == runtimeName {
				log.Infof("Ignoring duplicated runtime %q from %v",
					runtimeName, parts)
				continue partsLoop
			}
		}

		r := &containerutilsTypes.RuntimeConfig{
			Name:       runtimeName,
			SocketPath: socketPath,
		}
		if namespace != "" {
			r.Extra = &containerutilsTypes.ExtraConfig{
				Namespace: namespace,
			}
		}

		rc = append(rc, r)
	}

	l.rc = rc

	igManager, err := igmanager.NewManager(l.rc)
	if err != nil {
		log.Warnf("Failed to create container-collection")
		log.Debugf("Failed to create container-collection: %s", err)
	}
	l.igManager = igManager
	return nil
}

func (l *LocalManager) Close() error {
	if l.igManager != nil {
		l.igManager.Close()
	}
	return nil
}

func (l *LocalManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	_, canEnrichEventFromMountNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	traceInstance := &localManagerTrace{
		manager:            l,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
		params:             params,
		gadgetInstance:     gadgetInstance,
		gadgetCtx:          gadgetContext,
	}

	if l.igManager == nil {
		traceInstance.enrichEvents = false
	}

	return traceInstance, nil
}

type localManagerTrace struct {
	manager         *LocalManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers, so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext

	eventWrappers map[datasource.DataSource]*compat.EventWrapperBase
}

func (l *localManagerTrace) Name() string {
	return OperatorInstanceName
}

func (l *localManagerTrace) PreGadgetRun() error {
	log := l.gadgetCtx.Logger()
	id := uuid.New()
	host := l.params.Get(Host).AsBool()

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: l.params.Get(ContainerName).AsString(),
		},
	}

	// If --host is set, we do not want to create the below map because we do not
	// want any filtering.
	if setter, ok := l.gadgetInstance.(MountNsMapSetter); ok {
		if !host {
			if l.manager.igManager == nil {
				return fmt.Errorf("container-collection isn't available")
			}

			// Create mount namespace map to filter by containers
			mountnsmap, err := l.manager.igManager.CreateMountNsMap(id.String(), containerSelector)
			if err != nil {
				return commonutils.WrapInErrManagerCreateMountNsMap(err)
			}

			log.Debugf("set mountnsmap for gadget")
			setter.SetMountNsMap(mountnsmap)

			l.mountnsmap = mountnsmap
		} else if l.manager.igManager == nil {
			log.Warn("container-collection isn't available: container enrichment and filtering won't work")
		}
	}

	if attacher, ok := l.gadgetInstance.(Attacher); ok {
		if l.manager.igManager == nil {
			if !host {
				return fmt.Errorf("container-collection isn't available")
			}

			log.Warn("container-collection isn't available: no containers will be traced")
		}

		l.attacher = attacher
		var containers []*containercollection.Container

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					l.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", container.K8s.ContainerName, ve)
				}

				log.Warnf("start tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}

			l.attachedContainers[container] = struct{}{}

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.Pid, container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.DetachContainer()")
			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.Pid, container.Mntns, container.Netns)
		}

		if l.manager.igManager != nil {
			l.subscriptionKey = id.String()
			log.Debugf("add subscription")
			containers = l.manager.igManager.Subscribe(
				l.subscriptionKey,
				containerSelector,
				func(event containercollection.PubSubEvent) {
					log.Debugf("%s: %s", event.Type.String(), event.Container.Runtime.ContainerID)
					switch event.Type {
					case containercollection.EventTypeAddContainer:
						attachContainerFunc(event.Container)
					case containercollection.EventTypeRemoveContainer:
						detachContainerFunc(event.Container)
					}
				},
			)
		}

		if host {
			// We need to attach this fake container for gadget which rely only on the
			// Attacher concept.
			containers = append(containers, &containercollection.Container{Pid: 1})
		}

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}

	return nil
}

func (l *localManagerTrace) PostGadgetRun() error {
	if l.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		l.manager.igManager.RemoveMountNsMap(l.subscriptionKey)
	}
	if l.subscriptionKey != "" {
		host := l.params.Get(Host).AsBool()

		log.Debugf("calling Unsubscribe()")
		l.manager.igManager.Unsubscribe(l.subscriptionKey)

		if l.attacher != nil {
			// emit detach for all remaining containers
			for container := range l.attachedContainers {
				l.attacher.DetachContainer(container)
			}

			if host {
				// Reciprocal operation of attaching fake container with PID 1 which is
				// needed by gadgets relying on the Attacher concept.
				l.attacher.DetachContainer(&containercollection.Container{Pid: 1})
			}
		}
	}
	return nil
}

func (l *localManagerTrace) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		l.manager.igManager.ContainerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		l.manager.igManager.ContainerCollection.EnrichEventByNetNs(event)
	}
}

func (l *localManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}
	l.enrich(ev)
	return nil
}

func (l *LocalManager) InstantiateDataOperator(ctx operators.GadgetContext) (operators.DataOperatorInstance, error) {
	traceInstance := &localManagerTrace{
		manager:            l,
		enrichEvents:       false,
		attachedContainers: make(map[*containercollection.Container]struct{}),
		params:             l.ParamDescs().ToParams(), // TODO
		gadgetCtx:          ctx,

		eventWrappers: make(map[datasource.DataSource]*compat.EventWrapperBase),
	}

	if l.igManager == nil {
		traceInstance.enrichEvents = false
	}

	// hack - this makes it possible to use the Attacher interface
	var ok bool
	traceInstance.gadgetInstance, ok = ctx.GetVar("ebpfInstance")
	if !ok {
		return nil, fmt.Errorf("getting ebpfInstance")
	}

	activate := true // TODO: change to false once snapshot_socket is not skipped anymore

	// Check, whether the gadget requested a map from us
	if t, ok := ctx.GetVar(gadgets.MntNsFilterMapName); ok {
		if _, ok := t.(*ebpf.Map); ok {
			ctx.Logger().Debugf("gadget requested map %s", gadgets.MntNsFilterMapName)
			activate = true
		}
	}

	// Check for data sources containing refererences to mntns/netns that we could enrich data for
	for _, ds := range ctx.GetDataSources() {
		mntnsFields := ds.GetFieldsWithTag("type:gadget_mntns_id")               // TODO: const
		netnsFields := ds.GetFieldsWithTag("type:gadget_netns_id", "name:netns") // TODO: const
		if len(mntnsFields) == 0 && len(netnsFields) == 0 {
			continue
		}

		ctx.Logger().Debugf("ds found: %q", ds.Name())

		activate = true

		var err error

		var mntnsField datasource.FieldAccessor
		var netnsField datasource.FieldAccessor

		for _, f := range mntnsFields {
			ctx.Logger().Debugf("using mntns enrichment")
			mntnsField = f
			mntnsField.SetHidden(true)
			// We only support one of those per DataSource for now
			break
		}
		for _, f := range netnsFields {
			ctx.Logger().Debugf("using netns enrichment")
			netnsField = f
			netnsField.SetHidden(true)
			// We only support one of those per DataSource for now
			break
		}

		traceInstance.eventWrappers[ds], err = compat.WrapAccessors(ds, mntnsField, netnsField)
		if err != nil {
			return nil, fmt.Errorf("registering accessors: %w", err)
		}
	}

	if !activate {
		return nil, nil
	}

	return traceInstance, nil
}

func (l *localManagerTrace) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
		{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *localManagerTrace) Prepare(gadgetCtx operators.GadgetContext) error {
	id := uuid.New()
	host := false // TODO

	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: "", // TODO l.params.Get(ContainerName).AsString(),
		},
	}

	if !host {
		if l.manager.igManager == nil {
			return fmt.Errorf("container-collection isn't available")
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := l.manager.igManager.CreateMountNsMap(id.String(), containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)

		l.mountnsmap = mountnsmap
	} else if l.manager.igManager == nil {
		log.Warn("container-collection isn't available: container enrichment and filtering won't work")
	}

	for ds, wrapper := range l.eventWrappers {
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			wr := &compat.EventWrapper{
				EventWrapperBase: wrapper,
				Data:             data,
			}
			if wrapper.MntnsidAccessor != nil {
				l.manager.igManager.ContainerCollection.EnrichEventByMntNs(wr)
			}
			if wrapper.NetnsidAccessor != nil {
				l.manager.igManager.ContainerCollection.EnrichEventByNetNs(wr)
			}
			return nil
		}, 0)
	}

	// using PreGadgetRun() for the time being to register attacher funcs
	err := l.PreGadgetRun()
	if err != nil {
		return fmt.Errorf("preGadgetRun: %w", err)
	}

	return nil
}

func (l *localManagerTrace) Start(ctx operators.GadgetContext) error {
	return nil
}

func init() {
	lm := &LocalManager{}
	operators.Register(lm)
	operators.RegisterOperator(lm)
}
