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

package gadgetservice

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/sirupsen/logrus"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

type PersistentGadgetHost struct {
	runtime     runtime.Runtime
	mu          sync.Mutex
	gadgetRuns  map[string]*GadgetRun
	waitingRoom map[*Subscriber]struct{}
}

func NewPersistentGadgetHost() *PersistentGadgetHost {
	return &PersistentGadgetHost{
		runtime:     local.New(),
		mu:          sync.Mutex{},
		gadgetRuns:  make(map[string]*GadgetRun),
		waitingRoom: make(map[*Subscriber]struct{}),
	}
}

func (h *PersistentGadgetHost) StopAndRemoveGadgetRun(id string) error {
	h.mu.Lock()
	gadgetRun, ok := h.gadgetRuns[id]
	if ok {
		delete(h.gadgetRuns, id)
	}
	h.mu.Unlock()

	if ok {
		gadgetRun.Stop()
		return nil
	}

	return errors.New("gadget run not found")
}

func (h *PersistentGadgetHost) AddGadgetRun(id string, trace *gadgetv1alpha1.Trace) error {
	h.mu.Lock()
	if _, ok := h.gadgetRuns[id]; ok {
		h.mu.Unlock()
		return errors.New("gadgetID already exists")
	}
	gadgetRun := &GadgetRun{
		host:        h,
		subscribers: make(map[*Subscriber]struct{}),
	}
	h.gadgetRuns[id] = gadgetRun
	h.mu.Unlock()

	// Try to initialize
	err := gadgetRun.init(trace)
	if err != nil {
		h.mu.Lock()
		delete(h.gadgetRuns, id)
		h.mu.Unlock()
		return err
	}

	// Run gadget...
	go gadgetRun.run()
	return nil
}

type Subscriber struct{}

type GadgetRun struct {
	host        *PersistentGadgetHost
	mu          sync.Mutex
	gadgetCtx   *gadgetcontext.GadgetContext
	subscribers map[*Subscriber]struct{}
	cancelFn    func()
}

func (r *GadgetRun) init(trace *gadgetv1alpha1.Trace) error {
	runtime := r.host.runtime

	// Run and clean up afterwards
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)

	gadgetCategory := trace.ObjectMeta.Labels["gadgetCategory"]
	gadgetName := trace.ObjectMeta.Labels["gadgetName"]
	params := trace.Spec.Parameters
	runID := trace.ObjectMeta.Labels["global-trace-id"]

	gadgetDesc := gadgetregistry.Get(gadgetCategory, gadgetName)
	if gadgetDesc == nil {
		logger.Warnf("gadget not found: %s/%s", gadgetCategory, gadgetName)
		return nil
	}

	// Initialize Operators
	err := operators.GetAll().Init(operators.GlobalParamsCollection()) // TODO
	if err != nil {
		logger.Warnf("initialize operators: %v", err)
		return err
	}

	ops := operators.GetOperatorsForGadget(gadgetDesc)

	operatorParams := ops.ParamCollection()
	err = operatorParams.CopyFromMap(params, "operator.")
	if err != nil {
		logger.Warnf("setting operator parameters: %v", err)
		return nil
	}

	parser := gadgetDesc.Parser()

	runtimeParams := runtime.ParamDescs().ToParams()
	err = runtimeParams.CopyFromMap(params, "runtime.")
	if err != nil {
		logger.Warnf("setting runtime parameters: %v", err)
		return nil
	}

	gadgetParamDescs := gadgetDesc.ParamDescs()
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()
	err = gadgetParams.CopyFromMap(params, "")
	if err != nil {
		logger.Warnf("setting gadget parameters: %v", err)
		return nil
	}

	if parser != nil {
		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			d, _ := json.Marshal(ev)
			logger.Info(string(d))
		})
	}

	ctx, cancel := context.WithCancel(context.Background())

	r.cancelFn = cancel

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx,
		runID,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		operatorParams,
		parser,
		logger,
	)
	r.gadgetCtx = gadgetCtx

	return nil
}

func (r *GadgetRun) run() error {
	// Hand over to runtime
	result, err := r.host.runtime.RunGadget(r.gadgetCtx)
	if err != nil {
		r.gadgetCtx.Logger().Errorf("running gadget: %v", err)
		return nil
	}

	if result != nil {
		// Update CR
	}

	return nil
}

func (r *GadgetRun) Subscribe(subscriber *Subscriber) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribers[subscriber] = struct{}{}
}

func (r *GadgetRun) Unsubscribe(subscriber *Subscriber) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.subscribers, subscriber)
}

// Stop sends a stop signal to the gadget run, cancelling its context
func (r *GadgetRun) Stop() {
	if r.cancelFn != nil {
		r.cancelFn()
	}
}
