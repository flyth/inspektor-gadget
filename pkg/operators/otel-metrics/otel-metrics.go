// Copyright 2024 The Inspektor Gadget authors
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

package otelmetrics

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	Name = "otel-metrics"
)

type otelMetricsOperator struct{}

func (m *otelMetricsOperator) Name() string {
	return Name
}

func (m *otelMetricsOperator) Init(params *params.Params) error {
	return nil
}

func (m *otelMetricsOperator) GlobalParams() api.Params {
	return nil
}

func (m *otelMetricsOperator) InstanceParams() api.Params {
	return nil
}

func (m *otelMetricsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	return nil, nil
}

func (m *otelMetricsOperator) Priority() int {
	return 50000
}

type otelMetricsOperatorInstance struct{}

func (m *otelMetricsOperatorInstance) Name() string {
	return Name
}

func (m *otelMetricsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *otelMetricsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}
