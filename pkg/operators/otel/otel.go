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

package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamOtelGrpcInsecure = "otel-grpc-insecure"
	ParamOtelTracerName   = "otel-tracer-name"
)

type otelOperator struct {
	tracerProvider *sdktrace.TracerProvider
}

func (o *otelOperator) Name() string {
	return "otel"
}

func (o *otelOperator) Init(params *params.Params) error {
	ctx := context.Background()

	var otlptracegrpcOptions []otlptracegrpc.Option

	if params.Get(ParamOtelGrpcInsecure).AsBool() {
		otlptracegrpcOptions = append(otlptracegrpcOptions, otlptracegrpc.WithInsecure())
	}

	exp, err := otlptracegrpc.New(ctx, otlptracegrpcOptions...)
	if err != nil {
		panic(err)
	}
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("InspektorGadget"),
		),
	)
	if err != nil {
		panic(err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	o.tracerProvider = tp
	return nil
}

func (o *otelOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          ParamOtelGrpcInsecure,
			Description:  "disable TLS from open telemetry gRPC endpoints",
			DefaultValue: "true", // TODO
			TypeHint:     api.TypeBool,
		},
	}
}

func (o *otelOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          ParamOtelTracerName,
			Description:  "name of the otel tracer to export; for multiple data sources use datasourcename:tracername",
			DefaultValue: "ig",
		},
	}
}

func (o *otelOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	params := apihelpers.ToParamDescs(o.InstanceParams()).ToParams()
	err := params.CopyFromMap(instanceParamValues, "")
	if err != nil {
		return nil, fmt.Errorf("evaluating parameters: %w", err)
	}
	tracer := o.tracerProvider.Tracer(params.Get(ParamOtelTracerName).AsString())
	return &otelOperatorInstance{
		tracer: tracer,
	}, nil
}

func (o *otelOperator) Priority() int {
	return 50000
}

type otelOperatorInstance struct {
	tracer trace.Tracer
}

func (o *otelOperatorInstance) Name() string {
	return "otel"
}

func (o *otelOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		opts := func(ds datasource.DataSource, data datasource.Data) (res []attribute.KeyValue) {
			for _, f := range ds.Accessors(false) {
				switch f.Type() {
				case api.Kind_CString, api.Kind_String:
					v, _ := f.String(data)
					res = append(res, attribute.String(f.Name(), v))
				case api.Kind_Uint8:
					v, _ := f.Uint8(data)
					res = append(res, attribute.Int(f.Name(), int(v)))
				case api.Kind_Uint16:
					v, _ := f.Uint16(data)
					res = append(res, attribute.Int(f.Name(), int(v)))
				case api.Kind_Uint32:
					v, _ := f.Uint32(data)
					res = append(res, attribute.Int64(f.Name(), int64(v)))
				case api.Kind_Uint64:
					v, _ := f.Uint64(data)
					res = append(res, attribute.Int64(f.Name(), int64(v)))
				case api.Kind_Int8:
					v, _ := f.Int8(data)
					res = append(res, attribute.Int(f.Name(), int(v)))
				case api.Kind_Int16:
					v, _ := f.Int16(data)
					res = append(res, attribute.Int(f.Name(), int(v)))
				case api.Kind_Int32:
					v, _ := f.Int32(data)
					res = append(res, attribute.Int(f.Name(), int(v)))
				case api.Kind_Int64:
					v, _ := f.Int64(data)
					res = append(res, attribute.Int64(f.Name(), v))
				}
			}
			return res
		}

		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			var span trace.Span
			_, span = o.tracer.Start(gadgetCtx.Context(), ds.Name(), trace.WithAttributes(opts(ds, data)...))
			defer span.End()
			return nil
		}, 50000)
	}
	return nil
}

func (o *otelOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *otelOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var OtelOperator = &otelOperator{}
