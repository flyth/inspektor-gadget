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

package gadgetrunner

import (
	"context"
	"fmt"

	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/enrichers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// GadgetRunner handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime
type GadgetRunner struct {
	ctx          context.Context
	id           string
	gadget       gadgets.Gadget
	gadgetParams params.Params
	runtime      runtime.Runtime
	columns      columnhelpers.Columns
	enrichers    enrichers.Enrichers
	logger       logger.Logger
	result       []byte
	resultError  error
}

func NewGadgetRunner(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	gadget gadgets.Gadget,
	columns columnhelpers.Columns,
	logger logger.Logger,
) *GadgetRunner {
	return &GadgetRunner{
		ctx:     ctx,
		id:      id,
		gadget:  gadget,
		runtime: runtime,
		columns: columns,
		logger:  logger,
	}
}

func (r *GadgetRunner) ID() string {
	return r.id
}

func (r *GadgetRunner) Context() context.Context {
	return r.ctx
}

func (r *GadgetRunner) Columns() columnhelpers.Columns {
	return r.columns
}

func (r *GadgetRunner) Runtime() runtime.Runtime {
	return r.runtime
}

func (r *GadgetRunner) Gadget() gadgets.Gadget {
	return r.gadget
}

func (r *GadgetRunner) Enrichers() enrichers.Enrichers {
	return r.enrichers
}

func (r *GadgetRunner) Logger() logger.Logger {
	return r.logger
}

func (r *GadgetRunner) SetResult(result []byte, resultError error) {
	r.result = result
	r.resultError = resultError
}

func (r *GadgetRunner) GetResult() ([]byte, error) {
	return r.result, r.resultError
}

func (r *GadgetRunner) GadgetParams() *params.Params {
	return &r.gadgetParams
}

// RunGadget is the main function of GadgetRunner and controls the lifecycle of the gadget
func (r *GadgetRunner) RunGadget(
	runtimeParams params.Params,
	enricherParamCollection params.ParamsCollection,
	enricherPerGadgetParamCollection params.ParamsCollection,
	gadgetParams params.Params,
) error {
	r.gadgetParams = gadgetParams
	r.enrichers = enrichers.GetEnrichersForGadget(r.gadget)
	err := r.enrichers.InitAll(enricherParamCollection)
	if err != nil {
		return fmt.Errorf("initializing enrichers: %w", err)
	}
	err = r.runtime.RunGadget(r, runtimeParams, enricherPerGadgetParamCollection, gadgetParams)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}
	return nil
}
