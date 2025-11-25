// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package json

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// TestArrayJSONOutput tests that array fields are correctly encoded as native JSON arrays
func TestArrayJSONOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		elemKind     api.Kind
		testData     any
		putFunc      func(datasource.FieldAccessor, datasource.Data, any) error
		expectedJSON string
	}{
		{
			name:     "uint32 array",
			elemKind: api.Kind_Uint32,
			testData: []uint32{100, 200, 300},
			putFunc: func(acc datasource.FieldAccessor, d datasource.Data, val any) error {
				return acc.PutUint32Array(d, val.([]uint32))
			},
			expectedJSON: `{"pids":[100,200,300]}`,
		},
		{
			name:     "empty uint32 array",
			elemKind: api.Kind_Uint32,
			testData: []uint32{},
			putFunc: func(acc datasource.FieldAccessor, d datasource.Data, val any) error {
				return acc.PutUint32Array(d, val.([]uint32))
			},
			expectedJSON: `{"pids":[]}`,
		},
		{
			name:     "int64 array",
			elemKind: api.Kind_Int64,
			testData: []int64{-100, 200, -300},
			putFunc: func(acc datasource.FieldAccessor, d datasource.Data, val any) error {
				return acc.PutInt64Array(d, val.([]int64))
			},
			expectedJSON: `{"pids":[-100,200,-300]}`,
		},
		{
			name:     "float64 array",
			elemKind: api.Kind_Float64,
			testData: []float64{1.5, 2.5, 3.5},
			putFunc: func(acc datasource.FieldAccessor, d datasource.Data, val any) error {
				return acc.PutFloat64Array(d, val.([]float64))
			},
			expectedJSON: `{"pids":[1.5,2.5,3.5]}`,
		},
		{
			name:     "string array",
			elemKind: api.Kind_String,
			testData: []string{"hello", "world", "test"},
			putFunc: func(acc datasource.FieldAccessor, d datasource.Data, val any) error {
				return acc.PutStringArray(d, val.([]string))
			},
			expectedJSON: `{"pids":["hello","world","test"]}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ds, err := datasource.New(datasource.TypeSingle, "event")
			require.NoError(t, err)

			acc, err := ds.AddArrayField("pids", tt.elemKind)
			require.NoError(t, err)

			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			defer ds.Release(data)

			// Write array
			err = tt.putFunc(acc, data, tt.testData)
			require.NoError(t, err)

			// Create JSON formatter
			formatter, err := New(ds)
			require.NoError(t, err)

			// Get JSON output
			jsonOut := formatter.Marshal(data)
			assert.Equal(t, tt.expectedJSON, string(jsonOut))
		})
	}
}

// TestMixedFieldsJSON tests JSON output with both regular and array fields
func TestMixedFieldsJSON(t *testing.T) {
	t.Parallel()

	ds, err := datasource.New(datasource.TypeSingle, "event")
	require.NoError(t, err)

	// Add regular fields
	nameAcc, err := ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	pidAcc, err := ds.AddField("pid", api.Kind_Uint32)
	require.NoError(t, err)

	// Add array field
	pidsAcc, err := ds.AddArrayField("pids", api.Kind_Uint32)
	require.NoError(t, err)

	// Create test data
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	defer ds.Release(data)

	err = nameAcc.PutString(data, "test_process")
	require.NoError(t, err)

	err = pidAcc.PutUint32(data, 12345)
	require.NoError(t, err)

	err = pidsAcc.PutUint32Array(data, []uint32{100, 200, 300})
	require.NoError(t, err)

	// Create JSON formatter
	formatter, err := New(ds)
	require.NoError(t, err)

	// Get JSON output
	jsonOut := formatter.Marshal(data)

	// Should contain all fields as native JSON types
	assert.Contains(t, string(jsonOut), `"name":"test_process"`)
	assert.Contains(t, string(jsonOut), `"pid":12345`)
	assert.Contains(t, string(jsonOut), `"pids":[100,200,300]`)
}
