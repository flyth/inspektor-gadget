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

package prometheus

import (
	"fmt"

	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/inspektor-gadget/inspektor-gadget/internal/enrichers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type SetMetricsExporter interface {
	SetMetricsExporter(metric.MeterProvider)
}

const (
	EnableStats = "enable-stats"
)

type Prometheus struct {
	exporter      *prometheus.Exporter
	meterProvider metric.MeterProvider
}

func (l *Prometheus) EnrichEvent(a any) error {
	return nil
}

func (l *Prometheus) Name() string {
	return "Prometheus"
}

func (l *Prometheus) Description() string {
	return "Provides a facility to export metrics using Prometheus"
}

func (l *Prometheus) Dependencies() []string {
	return nil
}

func (l *Prometheus) Params() params.Params {
	return nil
}

func (l *Prometheus) PerGadgetParams() params.Params {
	return params.Params{
		{
			Key:          EnableStats,
			Alias:        "",
			Title:        "Enable Stats Export",
			DefaultValue: "false",
			Description:  "Enables collecting stats from the gadget and export it via Prometheus",
			IsMandatory:  true,
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *Prometheus) Init(enricherParams params.Params) error {
	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("initialize prometheus exporter: %w", err)
	}
	l.exporter = exporter
	l.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	return nil
}

func (l *Prometheus) CanEnrich(gadget gadgets.Gadget) bool {
	inst, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}
	tempInstance, err := inst.NewInstance(nil)
	if err != nil {
		return false
	}
	if _, ok := tempInstance.(SetMetricsExporter); !ok {
		return false
	}
	return true
}

func (l *Prometheus) Cleanup() error {
	return nil
}

func (l *Prometheus) PreGadgetRun(runner enrichers.Runner, tracer any, perGadgetParams params.Params) (enrichers.Enricher, error) {
	if perGadgetParams.ParamMap()[EnableStats] != "true" {
		return l, nil
	}
	if setter, ok := tracer.(SetMetricsExporter); ok {
		setter.SetMetricsExporter(l.meterProvider)
	}
	return l, nil
}

func (l *Prometheus) PostGadgetRun() error {
	return nil
}

func init() {
	enrichers.RegisterEnricher(&Prometheus{})
}
