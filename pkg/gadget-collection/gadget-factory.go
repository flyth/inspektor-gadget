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

package gadgetcollection

import (
	"errors"
	"fmt"
	"sync"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	gadgets2 "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Factory is a generic factory for all gadgets
// TODO: right now only for trace gadgets
type Factory struct {
	gadgets.Gadget

	Helpers gadgets2.GadgetHelpers
	Client  client.Client

	// DeleteTrace is optionally set by gadgets if they need to do
	// specialised clean up. Example:
	//
	// func NewFactory() gadgets.TraceFactory {
	// 	return &TraceFactory{
	// 		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	// 	}
	// }
	DeleteTrace func(name string, trace any)

	mu     sync.Mutex
	traces map[string]any
}

// Operations creates a TraceOperation map for backward compatibility
func (f *Factory) Operations() map[gadgetv1alpha1.Operation]gadgets2.TraceOperation {
	return map[gadgetv1alpha1.Operation]gadgets2.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: fmt.Sprintf("Start %s gadget", f.Gadget.Name()),
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				// f.LookupOrCreate(name, n).(*Trace).Start(trace)
				/*

					Perform in Start():
					* get a TraceName(): traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
					* register EventCallback
					* validate trace.Spec.Parameters and build Config object
					* t.helpers.MountNsMap(traceName)
					* tracer.NewTracer()
					* trace.Status.State = gadgetv1alpha1.TraceStateStarted

					Snapshot Gadget do more!

				*/
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: fmt.Sprintf("Stop %s gadget", f.Gadget.Name()),
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				// f.LookupOrCreate(name, n).(*Trace).Stop(trace)
				/*

					Perform in Stop():
					* tracer.Stop()
					* trace.Status.State = gadgetv1alpha1.TraceStateStopped

				*/
			},
		},
	}
}

// OutputModesSupported creates a TraceOutput map for backward compatibility
func (f *Factory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	switch f.Gadget.Type() {
	case gadgets.TypeOneShot:
		return map[gadgetv1alpha1.TraceOutputMode]struct{}{
			gadgetv1alpha1.TraceOutputModeStatus: {},
		}
	case gadgets.TypeTrace, gadgets.TypeTraceIntervals:
		return map[gadgetv1alpha1.TraceOutputMode]struct{}{
			gadgetv1alpha1.TraceOutputModeStream: {},
		}
	}
	return nil
}

// From BaseFactory
func (f *Factory) Initialize(h gadgets2.GadgetHelpers, c client.Client) {
	f.Helpers = h
	f.Client = c
}

func (f *Factory) LookupOrCreate(name string, newTrace func() any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.traces == nil {
		f.traces = make(map[string]any)
	} else {
		trace, ok := f.traces[name]
		if ok {
			return trace
		}
	}

	if newTrace == nil {
		return nil
	}

	trace := newTrace()
	f.traces[name] = trace

	return trace
}

func (f *Factory) Lookup(name string) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.traces == nil {
		return nil, errors.New("traces map is nil")
	}

	trace, ok := f.traces[name]
	if !ok {
		return nil, fmt.Errorf("no trace for name %q", name)
	}

	return trace, nil
}

func (f *Factory) Delete(name string) {
	log.Infof("Deleting %s", name)
	f.mu.Lock()
	defer f.mu.Unlock()
	trace, ok := f.traces[name]
	if !ok {
		log.Infof("Deleting %s: does not exist", name)
		return
	}
	if f.DeleteTrace != nil {
		f.DeleteTrace(name, trace)
	}
	delete(f.traces, name)
}
