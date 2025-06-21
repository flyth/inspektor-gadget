// Copyright 2025 The Inspektor Gadget authors
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

package expr

import (
	"context"
	"testing"

	expr2 "github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	dsexpr "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/expr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// TestStringFunctionConstraintMerge tests the Merge method of StringFunctionConstraint
func TestStringFunctionConstraintMerge(t *testing.T) {
	tests := []struct {
		name      string
		c1        *StringFunctionConstraint
		c2        Constraint
		expected  bool
		resultMsg string
	}{
		{
			name:      "startsWith with matching equals",
			c1:        NewStringFunctionConstraint("field", "startsWith", "pre"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "startsWith with non-matching equals",
			c1:        NewStringFunctionConstraint("field", "startsWith", "pre"),
			c2:        NewEqualsConstraint("field", "suffix"),
			expected:  false,
			resultMsg: "equals value doesn't match prefix",
		},
		{
			name:      "endsWith with matching equals",
			c1:        NewStringFunctionConstraint("field", "endsWith", "fix"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "endsWith with non-matching equals",
			c1:        NewStringFunctionConstraint("field", "endsWith", "fix"),
			c2:        NewEqualsConstraint("field", "nonmatching"),
			expected:  false,
			resultMsg: "equals value doesn't match suffix",
		},
		{
			name:      "contains with matching equals",
			c1:        NewStringFunctionConstraint("field", "contains", "ref"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "contains with non-matching equals",
			c1:        NewStringFunctionConstraint("field", "contains", "xyz"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  false,
			resultMsg: "equals value doesn't contain substring",
		},
		{
			name:      "same string function",
			c1:        NewStringFunctionConstraint("field", "startsWith", "pre"),
			c2:        NewStringFunctionConstraint("field", "startsWith", "pre"),
			expected:  true,
			resultMsg: "same function and value",
		},
		{
			name:      "different string function",
			c1:        NewStringFunctionConstraint("field", "startsWith", "pre"),
			c2:        NewStringFunctionConstraint("field", "endsWith", "fix"),
			expected:  false,
			resultMsg: "different function",
		},
		{
			name:      "different field names",
			c1:        NewStringFunctionConstraint("field1", "startsWith", "pre"),
			c2:        NewStringFunctionConstraint("field2", "startsWith", "pre"),
			expected:  false,
			resultMsg: "different field names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := tt.c1.Merge(tt.c2)
			assert.Equal(t, tt.expected, ok, tt.resultMsg)
			if ok {
				assert.NotNil(t, result, "Merge succeeded but returned nil constraint")
			}
		})
	}
}

// TestStringFunctionOffloader tests the StringFunctionOffloader
func TestStringFunctionOffloader(t *testing.T) {
	// Create a string function offloader for the "command" field
	offloader := StringFunctionOffloader("command")

	// Test the CheckCallback with various constraints
	t.Run("CheckCallback", func(t *testing.T) {
		// Test with a startsWith constraint
		startsWithConstraint := NewStringFunctionConstraint("command", "startsWith", "test")
		ok, err := offloader.CheckCallback(startsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "startsWith constraint should be supported")

		// Test with an endsWith constraint
		endsWithConstraint := NewStringFunctionConstraint("command", "endsWith", "test")
		ok, err = offloader.CheckCallback(endsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "endsWith constraint should be supported")

		// Test with a contains constraint
		containsConstraint := NewStringFunctionConstraint("command", "contains", "test")
		ok, err = offloader.CheckCallback(containsConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "contains constraint should be supported")

		// Test with an unsupported function
		unsupportedConstraint := NewStringFunctionConstraint("command", "matches", "test")
		ok, err = offloader.CheckCallback(unsupportedConstraint)
		assert.NoError(t, err)
		assert.False(t, ok, "matches constraint should not be supported")

		// Test with a different field name
		wrongFieldConstraint := NewStringFunctionConstraint("container", "startsWith", "test")
		ok, err = offloader.CheckCallback(wrongFieldConstraint)
		assert.NoError(t, err)
		assert.False(t, ok, "constraint for different field should not be supported")

		// Test with an equals constraint
		equalsConstraint := NewEqualsConstraint("command", "test")
		ok, err = offloader.CheckCallback(equalsConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "equals constraint should be supported")
	})

	// Test the OffloadCallback with various constraints
	t.Run("OffloadCallback", func(t *testing.T) {
		ctx := context.Background()

		// Test with a startsWith constraint
		startsWithConstraint := NewStringFunctionConstraint("command", "startsWith", "test")
		ok, err := offloader.OffloadCallback(ctx, startsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "startsWith constraint should be offloadable")

		// Test with an endsWith constraint
		endsWithConstraint := NewStringFunctionConstraint("command", "endsWith", "test")
		ok, err = offloader.OffloadCallback(ctx, endsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "endsWith constraint should be offloadable")

		// Test with a contains constraint
		containsConstraint := NewStringFunctionConstraint("command", "contains", "test")
		ok, err = offloader.OffloadCallback(ctx, containsConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "contains constraint should be offloadable")

		// Test with an unsupported function
		unsupportedConstraint := NewStringFunctionConstraint("command", "matches", "test")
		ok, err = offloader.OffloadCallback(ctx, unsupportedConstraint)
		assert.Error(t, err)
		assert.False(t, ok, "matches constraint should not be offloadable")

		// Test with an equals constraint
		equalsConstraint := NewEqualsConstraint("command", "test")
		ok, err = offloader.OffloadCallback(ctx, equalsConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "equals constraint should be offloadable")

		// Test with an unsupported constraint type
		unsupportedTypeConstraint := NewRangeConstraint("command", 1, 10)
		ok, err = offloader.OffloadCallback(ctx, unsupportedTypeConstraint)
		assert.Error(t, err)
		assert.False(t, ok, "range constraint should not be offloadable for string field")
	})
}

// TestStringFunctionIntegration tests the integration of string function constraints with the OffloadPatcher
func TestStringFunctionIntegration(t *testing.T) {
	// Create a datasource for testing
	ds, err := datasource.New(datasource.TypeSingle, "Test")
	require.NoError(t, err)

	_, err = ds.AddField("command", api.Kind_String)
	require.NoError(t, err)

	// Create the datasource patcher
	dsp := dsexpr.DSPatcher{
		Datasource: ds,
	}

	// Get expression options
	options := dsexpr.GetBuiltInExpressions()
	options = append(options, expr2.AsBool(), expr2.Env(datasource.Data(nil)))

	// Test cases for string function expressions
	testCases := []struct {
		name           string
		filter         string
		shouldActivate bool
	}{
		{
			name:           "startsWith function",
			filter:         "command.startsWith('test')",
			shouldActivate: true,
		},
		{
			name:           "endsWith function",
			filter:         "command.endsWith('test')",
			shouldActivate: true,
		},
		{
			name:           "contains function",
			filter:         "command.contains('test')",
			shouldActivate: true,
		},
		{
			name:           "AND with startsWith",
			filter:         "command.startsWith('test') && command.endsWith('ing')",
			shouldActivate: true,
		},
		{
			name:           "OR with contains",
			filter:         "command.contains('test') || command.contains('other')",
			shouldActivate: true,
		},
		{
			name:           "equals with string function",
			filter:         "command == 'test' || command.startsWith('other')",
			shouldActivate: false,
		},
		{
			name:           "unsupported function",
			filter:         "command.matches('test')",
			shouldActivate: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the offload patcher
			op := NewOffloadPatcher()
			op.RegisterOffloader("command", StringFunctionOffloader("command"))

			// Compile the filter
			_, err := Compile(tc.filter, op, dsp, options...)
			require.NoError(t, err)

			activated := op.activated["command"]
			assert.Equal(t, tc.shouldActivate, activated, "Offloader activation status mismatch")
		})
	}
}
