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

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	expr2 "github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/checker"
	"github.com/expr-lang/expr/compiler"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/optimizer"
	"github.com/expr-lang/expr/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/expr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// OffloaderFactory functions for testing
func ContainerOffloader() *OffloadInfo {
	// Create a constraint handler for the Container offloader
	handler := NewConstraintHandler("container").WithMaxSetSize(10)

	return &OffloadInfo{
		Name: "container",
		CheckCallback: func(c any) (bool, error) {
			// Use the generic constraint handler
			return handler.CheckGenericConstraint(c)
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Use the string-specific helper
				return handler.ActivateStringEqualsConstraint(ctx, constraint,
					func(ctx context.Context, value string) (bool, error) {
						// Actual eBPF program configuration would happen here
						handler.Logger.Debugf("Activating container filter for ID: %s", value)
						return true, nil
					})

			case *SetConstraint:
				// Use the set-specific helper
				return handler.ActivateStringSetConstraint(ctx, constraint,
					func(ctx context.Context, values []string) (bool, error) {
						handler.Logger.Debugf("Activating container filter for multiple IDs: %v", values)
						return true, nil
					})

			default:
				return false, fmt.Errorf("unsupported constraint type for container offload: %T", c)
			}
		},
	}
}

func ParamOffloader() *OffloadInfo {
	// Create a constraint handler for the PID offloader
	handler := NewConstraintHandler("pid").WithMaxSetSize(16)

	return &OffloadInfo{
		Name: "pid",
		CheckCallback: func(c any) (bool, error) {
			// Use the generic constraint handler
			return handler.CheckGenericConstraint(c)
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Use the numeric-specific helper
				return handler.ActivateNumericEqualsConstraint(ctx, constraint,
					func(ctx context.Context, value int64) (bool, error) {
						// Actual eBPF program configuration would happen here
						handler.Logger.Debugf("Activating PID filter for: %d", value)
						return true, nil
					})

			case *RangeConstraint:
				// Use the range-specific helper
				return handler.ActivateNumericRangeConstraint(ctx, constraint,
					func(ctx context.Context, min, max *int64) (bool, error) {
						// Handle special multi-range type
						if constraint.Type() == "multi-range" {
							handler.Logger.Debugf("Activating PID multi-range filter")
							return true, nil
						}

						// Normal range handling
						handler.Logger.Debugf("Activating PID range filter: min=%v, max=%v", min, max)
						return true, nil
					})

			case *SetConstraint:
				// Use the set-specific helper
				return handler.ActivateNumericSetConstraint(ctx, constraint,
					func(ctx context.Context, values []int64) (bool, error) {
						handler.Logger.Debugf("Activating PID filter for multiple values: %v", values)
						return true, nil
					})

			default:
				return false, fmt.Errorf("unsupported constraint type for PID offload: %T", c)
			}
		},
	}
}

// Helper function to compile a filter expression with the offloader
func compileFilter(t *testing.T, filter string, op *OffloadPatcher) (*vm.Program, error) {
	// Create a datasource for testing
	ds, err := datasource.New(datasource.TypeSingle, "Test")
	require.NoError(t, err)

	_, err = ds.AddField("container", api.Kind_String)
	require.NoError(t, err)

	_, err = ds.AddField("pid", api.Kind_Uint32)
	require.NoError(t, err)

	_, err = ds.AddField("command", api.Kind_String)
	require.NoError(t, err)

	// Create the datasource patcher
	dsp := expr.DSPatcher{
		Datasource: ds,
	}

	// Get expression options
	options := expr.GetBuiltInExpressions()
	options = append(options, expr2.AsBool(), expr2.Env(datasource.Data(nil)))

	// Compile the filter
	config := conf.CreateNew()
	for _, opt := range options {
		opt(config)
	}
	for name := range config.Disabled {
		delete(config.Builtins, name)
	}
	config.Check()
	config.Strict = false

	tree, err := checker.ParseCheck(filter, config)
	if err != nil {
		return nil, err
	}

	// First pass: let our offloader visit each node
	Walk(&tree.Node, op)

	// Second pass: normal AST walking for the DSPatcher
	ast.Walk(&tree.Node, dsp)

	if config.Optimize {
		err = optimizer.Optimize(&tree.Node, config)
		if err != nil {
			var fileError *file.Error
			if errors.As(err, &fileError) {
				return nil, fileError.Bind(tree.Source)
			}
			return nil, err
		}
	}

	program, err := compiler.Compile(tree, config)
	if err != nil {
		return nil, err
	}

	return program, nil
}

// Test cases
func TestSimpleEqualityOffloadable(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "container == 'a'"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that the container offloader was activated
	activated := op.activated["container"]
	assert.True(t, activated, "Container offloader should be activated")
}

func TestORWithSameFieldOffloadable(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "container == 'a' || container == 'b'"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that the container offloader was activated
	activated := op.activated["container"]
	assert.True(t, activated, "Container offloader should be activated for OR with same field")
}

func TestANDWithDifferentFieldsOffloadable(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "container == 'a' && pid == 1"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that both offloaders were activated
	containerActivated := op.activated["container"]
	pidActivated := op.activated["pid"]

	assert.True(t, containerActivated, "Container offloader should be activated")
	assert.True(t, pidActivated, "PID offloader should be activated")
}

func TestANDWithRangeOffloadable(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "pid > 100 && pid < 1000"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that the PID offloader was activated
	activated := op.activated["pid"]
	assert.True(t, activated, "PID offloader should be activated for range")
}

func TestMixedWithNonOffloadablePart(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "container == 'a' || (command == 'test' && pid == 1)"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that only the container offloader was activated
	containerActivated := op.activated["container"]
	pidActivated := op.activated["pid"]

	assert.True(t, containerActivated, "Container offloader should be activated")
	// While pid is offloadable, it's part of a non-offloadable expression with command
	// so the pid offloader shouldn't be activated in the complex part
	assert.False(t, pidActivated, "PID offloader should not be activated in this complex case")
}

func TestComplexFilterWithMultipleParts(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "(container == 'a' || container == 'b') && (pid < 100 || pid > 1000)"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that both offloaders were activated
	containerActivated := op.activated["container"]
	pidActivated := op.activated["pid"]

	assert.True(t, containerActivated, "Container offloader should be activated")
	assert.True(t, pidActivated, "PID offloader should be activated")
}

func TestContradictoryConstraints(t *testing.T) {
	// Set up the offload patcher
	op := NewOffloadPatcher()
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Compile the filter
	filter := "pid < 10 && pid > 20"
	_, err := compileFilter(t, filter, op)
	require.NoError(t, err)

	// Check that no offloaders were activated due to contradiction
	activated := op.activated["pid"]
	assert.False(t, activated, "PID offloader should not be activated due to contradiction")
}

func TestAllTestCases(t *testing.T) {
	// Define all test cases
	testCases := []struct {
		name              string
		filter            string
		expectedContainer bool
		expectedPid       bool
	}{
		{
			name:              "Simple equality offloadable",
			filter:            "container == 'a'",
			expectedContainer: true,
			expectedPid:       false,
		},
		{
			name:              "OR with same field offloadable",
			filter:            "container == 'a' || container == 'b'",
			expectedContainer: true,
			expectedPid:       false,
		},
		{
			name:              "AND with different fields offloadable",
			filter:            "container == 'a' && pid == 1",
			expectedContainer: true,
			expectedPid:       true,
		},
		{
			name:              "AND with range offloadable",
			filter:            "pid > 100 && pid < 1000",
			expectedContainer: false,
			expectedPid:       true,
		},
		{
			name:              "Mixed with non-offloadable part",
			filter:            "container == 'a' || (command == 'test' && pid == 1)",
			expectedContainer: true,
			expectedPid:       false,
		},
		{
			name:              "Complex filter with multiple parts",
			filter:            "(container == 'a' || container == 'b') && (pid < 100 || pid > 1000)",
			expectedContainer: true,
			expectedPid:       true,
		},
		{
			name:              "Contradictory constraints",
			filter:            "pid < 10 && pid > 20",
			expectedContainer: false,
			expectedPid:       false,
		},
	}

	// Run all tests
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the offload patcher
			op := NewOffloadPatcher()
			op.RegisterOffloader("container", ContainerOffloader())
			op.RegisterOffloader("pid", ParamOffloader())

			// Compile the filter
			_, err := compileFilter(t, tc.filter, op)
			require.NoError(t, err)

			// Check that the expected offloaders were activated
			containerActivated := op.activated["container"]
			pidActivated := op.activated["pid"]

			assert.Equal(t, tc.expectedContainer, containerActivated,
				"Container offloader activation status mismatch for %s", tc.name)
			assert.Equal(t, tc.expectedPid, pidActivated,
				"PID offloader activation status mismatch for %s", tc.name)
		})
	}
}
