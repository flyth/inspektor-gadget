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
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func TestMetricsCounter(
	t *testing.T,
) {
	o := &otelMetricsOperator{skipListen: true}
	err := o.Init(apihelpers.ToParamDescs(o.GlobalParams()).ToParams())
	assert.NoError(t, err)

	var ds datasource.DataSource
	var ctr datasource.FieldAccessor

	var wg sync.WaitGroup
	wg.Add(1)

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		assert.NoError(t, err)
		ds.AddAnnotation("metrics.enable", "true")
		ctr, err = ds.AddField("ctr", api.Kind_Uint32)
		assert.NoError(t, err)
		err = ctr.AddAnnotation("metrics.type", "counter")
		assert.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for range 10 {
			data, err := ds.NewPacketSingle()
			assert.NoError(t, err)
			err = ctr.PutUint32(data, uint32(1))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		wg.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error {
			// Remove me once OnStop in SimpleOperator is fixed
			return nil
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{})
	assert.NoError(t, err)

	wg.Wait()

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	assert.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		found := false
		for _, m := range sm.Metrics {
			if m.Name == "ctr" {
				found = true
				data, ok := (m.Data).(metricdata.Sum[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(10), data.DataPoints[0].Value)
			}
		}
		assert.True(t, found)
	}
}

func TestMetricsHistogram(
	t *testing.T,
) {
	o := &otelMetricsOperator{skipListen: true}
	err := o.Init(apihelpers.ToParamDescs(o.GlobalParams()).ToParams())
	assert.NoError(t, err)

	var ds datasource.DataSource
	var value datasource.FieldAccessor

	var wg sync.WaitGroup
	wg.Add(1)

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		assert.NoError(t, err)
		ds.AddAnnotation("metrics.enable", "true")
		value, err = ds.AddField("duration", api.Kind_Uint32)
		assert.NoError(t, err)
		err = value.AddAnnotation("metrics.type", "histogram")
		assert.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for i := range 10 {
			data, err := ds.NewPacketSingle()
			assert.NoError(t, err)
			err = value.PutUint32(data, uint32((i+1)*10000000))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		wg.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error {
			// Remove me once OnStop in SimpleOperator is fixed
			return nil
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{})
	assert.NoError(t, err)

	wg.Wait()

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	assert.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		found := false
		for _, m := range sm.Metrics {
			if m.Name == "duration" {
				found = true
				data, ok := (m.Data).(metricdata.Histogram[int64])
				assert.True(t, ok)
				// assert.Equal(t, int64(10), data.DataPoints[0])
				log.Printf("%+v", data.DataPoints[0])
			}
		}
		assert.True(t, found)
	}
}
