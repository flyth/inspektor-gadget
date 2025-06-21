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
			c1:        NewStringFunctionConstraint("field", FunctionStartsWith, "pre"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "startsWith with non-matching equals",
			c1:        NewStringFunctionConstraint("field", FunctionStartsWith, "pre"),
			c2:        NewEqualsConstraint("field", "suffix"),
			expected:  false,
			resultMsg: "equals value doesn't match prefix",
		},
		{
			name:      "endsWith with matching equals",
			c1:        NewStringFunctionConstraint("field", FunctionEndsWith, "fix"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "endsWith with non-matching equals",
			c1:        NewStringFunctionConstraint("field", FunctionEndsWith, "fix"),
			c2:        NewEqualsConstraint("field", "nonmatching"),
			expected:  false,
			resultMsg: "equals value doesn't match suffix",
		},
		{
			name:      "contains with matching equals",
			c1:        NewStringFunctionConstraint("field", FunctionContains, "ref"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "contains with non-matching equals",
			c1:        NewStringFunctionConstraint("field", FunctionContains, "xyz"),
			c2:        NewEqualsConstraint("field", "prefix"),
			expected:  false,
			resultMsg: "equals value doesn't contain substring",
		},
		{
			name:      "same string function",
			c1:        NewStringFunctionConstraint("field", FunctionStartsWith, "pre"),
			c2:        NewStringFunctionConstraint("field", FunctionStartsWith, "pre"),
			expected:  true,
			resultMsg: "same function and value",
		},
		{
			name:      "different string function",
			c1:        NewStringFunctionConstraint("field", FunctionStartsWith, "pre"),
			c2:        NewStringFunctionConstraint("field", FunctionEndsWith, "fix"),
			expected:  false,
			resultMsg: "different function",
		},
		{
			name:      "different field names",
			c1:        NewStringFunctionConstraint("field1", FunctionStartsWith, "pre"),
			c2:        NewStringFunctionConstraint("field2", FunctionStartsWith, "pre"),
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
		startsWithConstraint := NewStringFunctionConstraint("command", FunctionStartsWith, "test")
		ok, err := offloader.CheckCallback(startsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "startsWith constraint should be supported")

		// Test with an endsWith constraint
		endsWithConstraint := NewStringFunctionConstraint("command", FunctionEndsWith, "test")
		ok, err = offloader.CheckCallback(endsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "endsWith constraint should be supported")

		// Test with a contains constraint
		containsConstraint := NewStringFunctionConstraint("command", FunctionContains, "test")
		ok, err = offloader.CheckCallback(containsConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "contains constraint should be supported")

		// Test with an unsupported function
		unsupportedConstraint := NewStringFunctionConstraint("command", "matches", "test")
		ok, err = offloader.CheckCallback(unsupportedConstraint)
		assert.NoError(t, err)
		assert.False(t, ok, "matches constraint should not be supported")

		// Test with a different field name
		wrongFieldConstraint := NewStringFunctionConstraint("container", FunctionStartsWith, "test")
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
		startsWithConstraint := NewStringFunctionConstraint("command", FunctionStartsWith, "test")
		ok, err := offloader.OffloadCallback(ctx, startsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "startsWith constraint should be offloadable")

		// Test with an endsWith constraint
		endsWithConstraint := NewStringFunctionConstraint("command", FunctionEndsWith, "test")
		ok, err = offloader.OffloadCallback(ctx, endsWithConstraint)
		assert.NoError(t, err)
		assert.True(t, ok, "endsWith constraint should be offloadable")

		// Test with a contains constraint
		containsConstraint := NewStringFunctionConstraint("command", FunctionContains, "test")
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

// TestMultiStringFunctionConstraint tests the StringFunctionConstraint struct with multiple conditions
func TestMultiStringFunctionConstraint(t *testing.T) {
	// Test creating a string-function constraint with multiple conditions
	conditions := []StringFunctionCondition{
		{Function: FunctionStartsWith, Value: "test"},
		{Function: FunctionEndsWith, Value: "ing"},
	}
	constraint := NewMultiStringFunctionConstraint("command", conditions, LogicalOperatorAND)

	// Check the constraint properties
	assert.Equal(t, "command", constraint.Name(), "Name should be 'command'")
	assert.Equal(t, ConstraintTypeStringFunction, constraint.Type(), "Type should be 'string-function'")
	assert.Equal(t, LogicalOperatorAND, constraint.LogicalOp, "LogicalOp should be 'AND'")
	assert.Len(t, constraint.Conditions, 2, "Should have 2 conditions")

	// Test creating a string-function constraint from a pair of string function constraints
	c1 := NewStringFunctionConstraint("command", FunctionStartsWith, "test")
	c2 := NewStringFunctionConstraint("command", FunctionEndsWith, "ing")
	multiConstraint := NewMultiStringFunctionConstraintFromPair(c1, c2, LogicalOperatorOR)

	// Check the constraint properties
	assert.Equal(t, "command", multiConstraint.Name(), "Name should be 'command'")
	assert.Equal(t, ConstraintTypeStringFunction, multiConstraint.Type(), "Type should be 'string-function'")
	assert.Equal(t, LogicalOperatorOR, multiConstraint.LogicalOp, "LogicalOp should be 'OR'")
	assert.Len(t, multiConstraint.Conditions, 2, "Should have 2 conditions")
	assert.Equal(t, FunctionStartsWith, multiConstraint.Conditions[0].Function, "First condition function should be 'startsWith'")
	assert.Equal(t, "test", multiConstraint.Conditions[0].Value, "First condition value should be 'test'")
	assert.Equal(t, FunctionEndsWith, multiConstraint.Conditions[1].Function, "Second condition function should be 'endsWith'")
	assert.Equal(t, "ing", multiConstraint.Conditions[1].Value, "Second condition value should be 'ing'")

	// Test merging with an equals constraint that satisfies both conditions
	eq := NewEqualsConstraint("command", "testing")

	// With OR logic, it should merge if at least one condition is satisfied
	result, ok := multiConstraint.Merge(eq)
	assert.True(t, ok, "Should be able to merge with equals constraint when LogicalOp is OR and at least one condition is satisfied")
	assert.Equal(t, eq, result, "Result should be the equals constraint")

	// Change to AND and try again
	multiConstraint.LogicalOp = LogicalOperatorAND
	result, ok = multiConstraint.Merge(eq)
	assert.True(t, ok, "Should be able to merge with equals constraint when LogicalOp is AND and all conditions are satisfied")
	assert.Equal(t, eq, result, "Result should be the equals constraint")

	// Test with an equals constraint that doesn't satisfy all conditions
	eq = NewEqualsConstraint("command", "test")
	result, ok = multiConstraint.Merge(eq)
	assert.False(t, ok, "Should not be able to merge with equals constraint when LogicalOp is AND and not all conditions are satisfied")

	// Change back to OR and try again
	multiConstraint.LogicalOp = LogicalOperatorOR
	result, ok = multiConstraint.Merge(eq)
	assert.True(t, ok, "Should be able to merge with equals constraint when LogicalOp is OR and at least one condition is satisfied")

	// Test with an equals constraint that doesn't satisfy any condition
	eq = NewEqualsConstraint("command", "xyz")
	result, ok = multiConstraint.Merge(eq)
	assert.False(t, ok, "Should not be able to merge with equals constraint when no condition is satisfied")

	// Test optimization for OR with startsWith conditions
	c1 = NewStringFunctionConstraint("command", FunctionStartsWith, "foo")
	c2 = NewStringFunctionConstraint("command", FunctionStartsWith, "foobar")
	optimizedConstraint := NewMultiStringFunctionConstraintFromPair(c1, c2, LogicalOperatorOR)

	// Should optimize to just the "foo" constraint since it's more general
	assert.Equal(t, c1, optimizedConstraint, "Should optimize to the more general startsWith constraint")
	assert.Len(t, optimizedConstraint.Conditions, 1, "Should have only one condition after optimization")
	assert.Equal(t, "foo", optimizedConstraint.Conditions[0].Value, "Should keep the shorter prefix")

	// Test optimization for AND with startsWith conditions
	c1 = NewStringFunctionConstraint("command", FunctionStartsWith, "foo")
	c2 = NewStringFunctionConstraint("command", FunctionStartsWith, "foobar")
	optimizedConstraint = NewMultiStringFunctionConstraintFromPair(c1, c2, LogicalOperatorAND)

	// Should optimize to just the "foobar" constraint since it's more specific
	assert.Equal(t, c2, optimizedConstraint, "Should optimize to the more specific startsWith constraint")
	assert.Len(t, optimizedConstraint.Conditions, 1, "Should have only one condition after optimization")
	assert.Equal(t, "foobar", optimizedConstraint.Conditions[0].Value, "Should keep the longer prefix")

	// Test optimization for AND with endsWith conditions
	c1 = NewStringFunctionConstraint("command", FunctionEndsWith, "bar")
	c2 = NewStringFunctionConstraint("command", FunctionEndsWith, "foobar")
	optimizedConstraint = NewMultiStringFunctionConstraintFromPair(c1, c2, LogicalOperatorAND)

	// Should optimize to just the "foobar" constraint since it's more specific
	assert.Equal(t, c2, optimizedConstraint, "Should optimize to the more specific endsWith constraint")
	assert.Len(t, optimizedConstraint.Conditions, 1, "Should have only one condition after optimization")
	assert.Equal(t, "foobar", optimizedConstraint.Conditions[0].Value, "Should keep the longer suffix")

	// Test optimization for AND with contains conditions
	c1 = NewStringFunctionConstraint("command", FunctionContains, "bar")
	c2 = NewStringFunctionConstraint("command", FunctionContains, "foobar")
	optimizedConstraint = NewMultiStringFunctionConstraintFromPair(c1, c2, LogicalOperatorAND)

	// Should optimize to just the "foobar" constraint since it's more specific
	assert.Equal(t, c2, optimizedConstraint, "Should optimize to the more specific contains constraint")
	assert.Len(t, optimizedConstraint.Conditions, 1, "Should have only one condition after optimization")
	assert.Equal(t, "foobar", optimizedConstraint.Conditions[0].Value, "Should keep the more specific substring")
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
