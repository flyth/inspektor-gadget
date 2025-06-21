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
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/expr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// OffloaderFactory functions for testing
func ContainerOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "container",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("CONTAINER checking constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				log.Printf("✅ CONTAINER: equals constraint is supported - value: %v", constraint.Value)
				return true, nil

			case *SetConstraint:
				// Container ID offload can support a set of container IDs
				// Check that the set size is manageable
				if len(constraint.Values) <= 10 { // Arbitrary limit for demonstration
					log.Printf("✅ CONTAINER: set constraint with %d values is supported - values: %v",
						len(constraint.Values), constraint.Values)
					return true, nil
				}
				log.Printf("❌ CONTAINER: set constraint too large for offload - limit 10, got %d values",
					len(constraint.Values))
				return false, nil

			default:
				log.Printf("❌ CONTAINER: constraint type %T not supported for offload", c)
				return false, nil
			}
		},
		OffloadCallback: func(c any) (bool, error) {
			log.Printf("CONTAINER activating offload for constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				containerID, ok := constraint.Value.(string)
				if !ok {
					return false, fmt.Errorf("container ID must be a string, got %T", constraint.Value)
				}

				// In a real implementation, this would configure the eBPF program
				log.Printf("> activating container filter for ID: %s", containerID)
				return true, nil

			case *SetConstraint:
				// In a real implementation, this would configure the eBPF program with multiple values
				log.Printf("> activating container filter for multiple IDs: %v", constraint.Values)
				return true, nil

			default:
				return false, fmt.Errorf("unsupported constraint type for container offload: %T", c)
			}
		},
	}
}

func ParamOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "pid",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("PID checking constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				log.Printf("✅ PID: equals constraint is supported - value: %v", constraint.Value)
				return true, nil

			case *RangeConstraint:
				// Check for special multi-range type (OR of ranges)
				if constraint.Type() == "multi-range" {
					log.Printf("✅ PID: multi-range constraint is supported (OR of ranges)")
					return true, nil
				}

				// PID offload supports regular range filters
				log.Printf("✅ PID: range constraint is supported - min: %v, max: %v",
					constraint.Min, constraint.Max)
				return true, nil

			case *SetConstraint:
				// PID offload can support a limited set of PIDs
				if len(constraint.Values) <= 16 { // Arbitrary limit for demonstration
					log.Printf("✅ PID: set constraint with %d values is supported - values: %v",
						len(constraint.Values), constraint.Values)
					return true, nil
				}
				log.Printf("❌ PID: set constraint too large for offload - limit 16, got %d values",
					len(constraint.Values))
				return false, nil

			default:
				log.Printf("❌ PID: constraint type %T not supported for offload", c)
				return false, nil
			}
		},
		OffloadCallback: func(c any) (bool, error) {
			log.Printf("PID activating offload for constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Handle different integer types
				var pidValue int64
				var ok bool

				switch v := constraint.Value.(type) {
				case int64:
					pidValue = v
					ok = true
				case int:
					pidValue = int64(v)
					ok = true
				case float64:
					pidValue = int64(v)
					ok = true
				default:
					ok = false
				}

				if !ok {
					return false, fmt.Errorf("PID must be a numeric value, got %T", constraint.Value)
				}

				// In a real implementation, this would configure the eBPF program
				log.Printf("> activating PID filter for: %d", pidValue)
				return true, nil

			case *RangeConstraint:
				// Handle special multi-range type for OR of ranges
				if constraint.Type() == "multi-range" {
					log.Printf("> activating PID multi-range filter with two separate ranges")
					return true, nil
				}

				// Convert min/max values to integers for consistency
				var minVal, maxVal interface{} = nil, nil

				// Handle min value if present
				if constraint.Min != nil {
					switch min := constraint.Min.(type) {
					case int64:
						minVal = min
					case int:
						minVal = int64(min)
					case float64:
						minVal = int64(min)
					default:
						log.Printf("WARNING: Unsupported min type: %T", constraint.Min)
					}
				}

				// Handle max value if present
				if constraint.Max != nil {
					switch max := constraint.Max.(type) {
					case int64:
						maxVal = max
					case int:
						maxVal = int64(max)
					case float64:
						maxVal = int64(max)
					default:
						log.Printf("WARNING: Unsupported max type: %T", constraint.Max)
					}
				}

				// In a real implementation, this would configure the eBPF program with a range
				log.Printf("> activating PID range filter: min=%v, max=%v", minVal, maxVal)
				return true, nil

			case *SetConstraint:
				// In a real implementation, this would configure the eBPF program with multiple values
				log.Printf("> activating PID filter for multiple values: %v", constraint.Values)
				return true, nil

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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
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
		name                string
		filter              string
		expectedContainer   bool
		expectedPid         bool
	}{
		{
			name:                "Simple equality offloadable",
			filter:              "container == 'a'",
			expectedContainer:   true,
			expectedPid:         false,
		},
		{
			name:                "OR with same field offloadable",
			filter:              "container == 'a' || container == 'b'",
			expectedContainer:   true,
			expectedPid:         false,
		},
		{
			name:                "AND with different fields offloadable",
			filter:              "container == 'a' && pid == 1",
			expectedContainer:   true,
			expectedPid:         true,
		},
		{
			name:                "AND with range offloadable",
			filter:              "pid > 100 && pid < 1000",
			expectedContainer:   false,
			expectedPid:         true,
		},
		{
			name:                "Mixed with non-offloadable part",
			filter:              "container == 'a' || (command == 'test' && pid == 1)",
			expectedContainer:   true,
			expectedPid:         false,
		},
		{
			name:                "Complex filter with multiple parts",
			filter:              "(container == 'a' || container == 'b') && (pid < 100 || pid > 1000)",
			expectedContainer:   true,
			expectedPid:         true,
		},
		{
			name:                "Contradictory constraints",
			filter:              "pid < 10 && pid > 20",
			expectedContainer:   false,
			expectedPid:         false,
		},
	}

	// Run all tests
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the offload patcher
			op := &OffloadPatcher{
				visited:    make(map[*ast.Node]struct{}),
				offloaders: make(map[string][]*OffloadInfo),
				activated:  make(map[string]bool),
			}
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
