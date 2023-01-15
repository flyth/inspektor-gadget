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

package enrichers

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runner interface {
	ID() string
	Columns() columnhelpers.Columns
	Gadget() gadgets.Gadget
	Context() context.Context
	Enrichers() Enrichers
	Logger() logger.Logger
}

type Enricher interface {
	// Name must return a unique name for the enricher
	Name() string

	// Description is an optional description to show to the user
	Description() string

	// Params will return global params (required) for this enricher
	Params() params.Params

	// PerGadgetParams will return params (required) per gadget instance of the enricher
	PerGadgetParams() params.Params

	// Dependencies can list other enrichers that this enricher depends on
	Dependencies() []string

	// CanEnrich should test whether it supports enriching the given gadget. Init has not
	// necessarily been called at this point.
	CanEnrich(gadgets.Gadget) bool

	// Init allows the enricher to initialize itself
	Init(params params.Params) error

	// Cleanup allows the enricher to clean up stuff prior to exiting
	Cleanup() error

	// PreGadgetRun is called before a gadget is started; the enricher must return something that implements enricher
	// This is useful to create a context for an enricher by wrapping it.
	// Params given here are the ones returned by PerGadgetParams()
	PreGadgetRun(Runner, any, params.Params) (Enricher, error)

	// PostGadgetRun is called on the enricher that was returned from PrepareTrace after a
	// gadget was stopped
	PostGadgetRun() error

	// EnrichEvent is called on the enricher returned by StartTrace and should perform
	// the actual enrichment
	EnrichEvent(any) error
}

type Enrichers []Enricher

// KubernetesFromMountNSID is a typical kubernetes enricher interface that adds node, pod, namespace and container
// information given the MountNSID
type KubernetesFromMountNSID interface {
	ContainerInfoSetters
	GetMountNSID() uint64
}

type ContainerInfoSetters interface {
	SetContainerInfo(pod, namespace, container string)
	SetNode(string)
}

var enrichers = map[string]Enricher{}

type enricherWrapper struct {
	Enricher
	initOnce    sync.Once
	initialized bool
}

func (e *enricherWrapper) Init(params params.Params) (err error) {
	e.initOnce.Do(func() {
		err = e.Enricher.Init(params)
		e.initialized = true
	})
	return err
}

func RegisterEnricher(enricher Enricher) error {
	// TODO: error checks
	log.Debugf("added enricher: %s", enricher.Name())
	enrichers[enricher.Name()] = enricher
	return nil
}

func EnrichersParamCollection() params.ParamsCollection {
	pc := make(params.ParamsCollection)
	for _, enricher := range enrichers {
		pc[enricher.Name()] = enricher.Params()
	}
	return pc
}

func GetEnrichersForGadget(gadget gadgets.Gadget) Enrichers {
	out := make(Enrichers, 0)
	for _, e := range enrichers {
		if e.CanEnrich(gadget) {
			out = append(out, e)
		}
	}
	out, err := SortEnrichers(out)
	if err != nil {
		panic(fmt.Sprintf("sorting enrichers: %v", err))
	}
	return out
}

func (e Enrichers) InitAll(pc params.ParamsCollection) error {
	for _, enricher := range e {
		err := enricher.Init(pc[enricher.Name()])
		if err != nil {
			return fmt.Errorf("initializing enricher %q: %w", enricher.Name(), err)
		}
	}
	return nil
}

func (e Enrichers) PerGadgetParamCollection() params.ParamsCollection {
	pc := make(params.ParamsCollection)
	for _, enricher := range e {
		pc[enricher.Name()] = enricher.PerGadgetParams()
	}
	return pc
}

func (e Enrichers) PreGadgetRun(runner Runner, trace any, perGadgetParamCollection params.ParamsCollection) error {
	for i, enricher := range e {
		ne, err := enricher.PreGadgetRun(runner, trace, perGadgetParamCollection[enricher.Name()])
		if err != nil {
			return fmt.Errorf("start trace on enricher %q: %w", enricher.Name(), err)
		}
		e[i] = ne
	}
	return nil
}

func (e Enrichers) PostGadgetRun() error {
	// TODO: Handling errors?
	for _, enricher := range e {
		enricher.PostGadgetRun()
	}
	return nil
}

// Enrich using multiple enrichers
func (e Enrichers) Enrich(ev any) {
	for _, enricher := range e {
		enricher.EnrichEvent(ev)
	}
}

func SortEnrichers(enrichers Enrichers) (Enrichers, error) {
	// Create a map to store the incoming edge count for each element
	incomingEdges := make(map[string]int)
	for _, e := range enrichers {
		// Initialize the incoming edge count for each element to zero
		incomingEdges[e.Name()] = 0
	}

	// Build the graph by adding an incoming edge for each dependency
	for _, e := range enrichers {
		for _, d := range e.Dependencies() {
			incomingEdges[d]++
		}
	}

	// Initialize the queue with all the elements that have zero incoming edges
	var queue []string
	for _, e := range enrichers {
		if incomingEdges[e.Name()] == 0 {
			queue = append(queue, e.Name())
		}
	}

	// Initialize the result slice
	var result Enrichers

	// Initialize the visited set
	visited := make(map[string]bool)

	// Process the queue
	for len(queue) > 0 {
		// Pop an element from the queue
		n := queue[0]
		queue = queue[1:]

		// Add the element to the visited set
		visited[n] = true

		// Prepend the element to the result slice
		for _, s := range enrichers {
			if s.Name() == n {
				result = append(Enrichers{s}, result...)
				break
			}
		}

		// Decrement the incoming edge count for each of the element's dependencies
		for _, d := range result[0].Dependencies() {
			incomingEdges[d]--
			// If a dependency's incoming edge count becomes zero, add it to the queue
			if incomingEdges[d] == 0 {
				queue = append(queue, d)
			}
			// If a dependency is already in the visited set, there is a cycle
			if visited[d] {
				return nil, fmt.Errorf("dependency cycle detected")
			}
		}
	}

	// Return an error if there are any unvisited elements, indicating that there is a cycle in the dependencies
	for _, e := range enrichers {
		if !visited[e.Name()] {
			return nil, fmt.Errorf("dependency cycle detected")
		}
	}

	return result, nil
}
