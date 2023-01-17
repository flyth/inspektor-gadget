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

package local

import (
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type EventHandlerSetter interface {
	SetEventHandler(handler any)
}

type EventEnricherSetter interface {
	SetEventEnricher(handler any)
}

type StartStopGadget interface {
	Start() error
	Stop()
}

// StartStopAltGadget is an alternative interface to StartStop, as some gadgets
// already have the Start() and Stop() functions defined, but with a different signature
// After we've migrated to the interfaces, the gadgets should be altered to use the
// Start/Stop signatures of the above StartStopGadget interface.
type StartStopAltGadget interface {
	StartAlt() error
	StopAlt()
}

type CloseGadget interface {
	Close()
}

type GadgetResult interface {
	Result() ([]byte, error)
}

func (r *Runtime) RunTraceGadget(runner runtime.Runner, gadget gadgets.GadgetInstantiate, enricherPerGadgetParamCollection params.ParamsCollection, params params.Params) error {
	log := runner.Logger()

	// Create gadget instance
	gadgetInstance, err := gadget.NewInstance(runner)
	if err != nil {
		return fmt.Errorf("instantiate gadget: %w", err)
	}

	// Deferring getting results and closing to make sure enrichers got their chance to clean up properly beforehand
	defer func() {
		if closer, ok := gadgetInstance.(CloseGadget); ok {
			log.Debugf("calling gadget.Close()")
			closer.Close()
		}
		if results, ok := gadgetInstance.(gadgets.GadgetResult); ok {
			res, err := results.Result()
			log.Debugf("setting result")
			runner.SetResult(res, err)
		}
	}()

	// Install enrichers
	err = runner.Enrichers().PreGadgetRun(runner, gadgetInstance, enricherPerGadgetParamCollection)
	if err != nil {
		return fmt.Errorf("starting enrichers: %w", err)
	}
	defer runner.Enrichers().PostGadgetRun()
	log.Debugf("found %d enrichers", len(runner.Enrichers()))

	if gadget.Type() == gadgets.TypeTraceIntervals {
		// Enable interval pushes
		log.Debugf("enabling snapshots")
		runner.Columns().EnableSnapshots(runner.Context(), time.Second, 2)
	}

	// Set event handler
	if setter, ok := gadgetInstance.(EventHandlerSetter); ok {
		log.Debugf("set event handler")
		switch gadget.Type() {
		default:
			setter.SetEventHandler(runner.Columns().EventHandlerFunc(runner.Enrichers().Enrich))
		case gadgets.TypeTraceIntervals:
			setter.SetEventHandler(runner.Columns().EventHandlerFuncSnapshot("main", runner.Enrichers().Enrich)) // TODO: "main" is the node
		}
	}

	// Set event handler
	if setter, ok := gadgetInstance.(EventEnricherSetter); ok {
		log.Debugf("set event enricher")
		setter.SetEventEnricher(runner.Enrichers().Enrich)
	}

	if startstop, ok := gadgetInstance.(StartStopAltGadget); ok {
		log.Debugf("calling gadget.StartAlt()")
		err := startstop.StartAlt()
		if err != nil {
			startstop.StopAlt()
			return fmt.Errorf("run gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.StopAlt()")
			startstop.StopAlt()
		}()
	} else if startstop, ok := gadgetInstance.(StartStopGadget); ok {
		log.Debugf("calling gadget.Start()")
		err := startstop.Start()
		if err != nil {
			startstop.Stop()
			return fmt.Errorf("run gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Stop()")
			startstop.Stop()
		}()
	}

	log.Debugf("running")

	if gadget.Type() != gadgets.TypeOneShot {
		// Wait for context to close
		<-runner.Context().Done()
	}

	log.Debugf("stopping gadget")
	return nil
}
