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
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name = "otel-metrics"
)

type otelMetricsOperator struct {
	exporter      *prometheus.Exporter
	meterProvider metric.MeterProvider
	initialized   bool
}

func (m *otelMetricsOperator) Name() string {
	return name
}

func (m *otelMetricsOperator) Init(globalParams *params.Params) error {
	if m.initialized {
		return nil
	}
	m.initialized = true
	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("initializing prometheus exporter: %v", err)
	}
	m.exporter = exporter
	m.meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe("0.0.0.0:2224", mux)
		if err != nil {
			log.Errorf("serving otel metrics on: %s", err)
			return
		}
	}()
	return nil
}

func (m *otelMetricsOperator) GlobalParams() api.Params {
	return nil
}

func (m *otelMetricsOperator) InstanceParams() api.Params {
	return nil
}

func (m *otelMetricsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	instance := &otelMetricsOperatorInstance{
		op:         m,
		collectors: make(map[datasource.DataSource]*metricsCollector),
	}
	err := instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (m *otelMetricsOperator) Priority() int {
	return 50000
}

type otelMetricsOperatorInstance struct {
	op         *otelMetricsOperator
	collectors map[datasource.DataSource]*metricsCollector
}

func (m *otelMetricsOperatorInstance) Name() string {
	return name
}

type metricsCollector struct {
	meter  metric.Meter
	keys   []func(datasource.Data) attribute.KeyValue
	values []func(context.Context, datasource.Data, attribute.Set)
}

func asInt64(f datasource.FieldAccessor) func(datasource.Data) int64 {
	switch f.Type() {
	default:
		return func(data datasource.Data) int64 {
			return 0
		}
	case api.Kind_Int8:
		return func(data datasource.Data) int64 {
			v, _ := f.Int8(data)
			return int64(v)
		}
	case api.Kind_Int16:
		return func(data datasource.Data) int64 {
			v, _ := f.Int16(data)
			return int64(v)
		}
	case api.Kind_Int32:
		return func(data datasource.Data) int64 {
			v, _ := f.Int32(data)
			return int64(v)
		}
	case api.Kind_Int64:
		return func(data datasource.Data) int64 {
			v, _ := f.Int64(data)
			return v
		}
	case api.Kind_Uint8:
		return func(data datasource.Data) int64 {
			v, _ := f.Uint8(data)
			return int64(v)
		}
	case api.Kind_Uint16:
		return func(data datasource.Data) int64 {
			v, _ := f.Uint16(data)
			return int64(v)
		}
	case api.Kind_Uint32:
		return func(data datasource.Data) int64 {
			v, _ := f.Uint32(data)
			return int64(v)
		}
	case api.Kind_Uint64:
		return func(data datasource.Data) int64 {
			v, _ := f.Uint64(data)
			return int64(v)
		}
	}
}

func asFloat64(f datasource.FieldAccessor) func(datasource.Data) float64 {
	switch f.Type() {
	default:
		return func(data datasource.Data) float64 {
			return 0
		}
	case api.Kind_Float32:
		return func(data datasource.Data) float64 {
			v, _ := f.Float32(data)
			return float64(v)
		}
	case api.Kind_Float64:
		return func(data datasource.Data) float64 {
			v, _ := f.Float64(data)
			return v
		}
	}
}

func (mc *metricsCollector) addKeyFunc(f datasource.FieldAccessor) error {
	name := f.Name()
	switch f.Type() {
	default:
		return fmt.Errorf("unsupported field type for metrics collector: %s", f.Type())
	case api.Kind_String, api.Kind_CString:
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			val, _ := f.String(data)
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.StringValue(val)}
		})
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		asIntFn := asInt64(f)
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.Int64Value(asIntFn(data))}
		})
	case api.Kind_Float32, api.Kind_Float64:
		asFloatFn := asFloat64(f)
		mc.keys = append(mc.keys, func(data datasource.Data) attribute.KeyValue {
			return attribute.KeyValue{Key: attribute.Key(name), Value: attribute.Float64Value(asFloatFn(data))}
		})
	}
	return nil
}

func (mc *metricsCollector) addValCtrFunc(f datasource.FieldAccessor) error {
	switch f.Type() {
	default:
		return fmt.Errorf("unsupported field type for metrics value %q: %s", f.Name(), f.Type())
	case api.Kind_Uint8,
		api.Kind_Uint16,
		api.Kind_Uint32,
		api.Kind_Uint64,
		api.Kind_Int8,
		api.Kind_Int16,
		api.Kind_Int32,
		api.Kind_Int64:
		ctr, err := mc.meter.Int64Counter(f.Name())
		if err != nil {
			return fmt.Errorf("adding metric counter for %q: %w", f.Name(), err)
		}
		asIntFn := asInt64(f)
		mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
			ctr.Add(ctx, asIntFn(data), metric.WithAttributeSet(set))
		})
		return nil
	case api.Kind_Float32, api.Kind_Float64:
		ctr, err := mc.meter.Float64Counter(f.Name())
		if err != nil {
			return fmt.Errorf("adding metric counter for %q: %w", f.Name(), err)
		}
		asFloatFn := asFloat64(f)
		mc.values = append(mc.values, func(ctx context.Context, data datasource.Data, set attribute.Set) {
			ctr.Add(ctx, asFloatFn(data), metric.WithAttributeSet(set))
		})
		return nil
	}
}

func (mc *metricsCollector) Collect(ctx context.Context, data datasource.Data) error {
	kvs := make([]attribute.KeyValue, 0, len(mc.keys))
	for _, kf := range mc.keys {
		kvs = append(kvs, kf(data))
	}
	kset := attribute.NewSet(kvs...)
	for _, vf := range mc.values {
		vf(ctx, data, kset)
	}
	return nil
}

func (m *otelMetricsOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		annotations := ds.Annotations()
		if annotations["metrics.enable"] != "true" {
			continue
		}

		metricsName := gadgetCtx.ImageName() // TODO: make this more unique?

		if name, ok := annotations["metrics.name"]; ok {
			metricsName = name
		}

		meter := m.op.meterProvider.Meter(metricsName)

		collector := &metricsCollector{meter: meter}

		fields := ds.Accessors(false)
		for _, f := range fields {
			fieldAnnotations := f.Annotations()
			switch fieldAnnotations["metrics.type"] {
			case "key":
				err := collector.addKeyFunc(f)
				if err != nil {
					return fmt.Errorf("adding key for %q: %w", f.Name(), err)
				}
			case "counter":
				err := collector.addValCtrFunc(f)
				if err != nil {
					return fmt.Errorf("adding counter for %q: %w", f.Name(), err)
				}
			}
		}

		m.collectors[ds] = collector
	}
	return nil
}

func (m *otelMetricsOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, collectors := range m.collectors {
		err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			return collectors.Collect(gadgetCtx.Context(), data)
		}, 50000)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *otelMetricsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *otelMetricsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var Operator = &otelMetricsOperator{}
