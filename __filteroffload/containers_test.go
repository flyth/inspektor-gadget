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
	"testing"

	"github.com/expr-lang/expr/ast"
	"github.com/stretchr/testify/assert"
)

func TestEqualsConstraintMerge(t *testing.T) {
	// Test merging two equal constraints with same value
	c1 := NewEqualsConstraint("container", "a")
	c2 := NewEqualsConstraint("container", "a")
	result, ok := c1.Merge(c2)

	assert.True(t, ok, "Should be able to merge identical equals constraints")
	assert.Equal(t, "a", result.(*EqualsConstraint).Value, "Merged constraint should have value 'a'")

	// Test merging two equal constraints with different values
	c1 = NewEqualsConstraint("container", "a")
	c2 = NewEqualsConstraint("container", "b")
	_, ok = c1.Merge(c2)

	assert.False(t, ok, "Should not be able to merge equals constraints with different values")

	// Test merging equals constraint with different field name
	c1 = NewEqualsConstraint("container", "a")
	c2 = NewEqualsConstraint("pid", "a")
	_, ok = c1.Merge(c2)

	assert.False(t, ok, "Should not be able to merge constraints with different field names")
}

func TestRangeConstraintMerge(t *testing.T) {
	// Test merging two overlapping range constraints
	c1 := NewRangeConstraint("pid", 10, 100)
	c2 := NewRangeConstraint("pid", 50, 150)
	result, ok := c1.Merge(c2)

	assert.True(t, ok, "Should be able to merge overlapping range constraints")
	assert.Equal(t, 50, result.(*RangeConstraint).Min, "Merged constraint should have min 50")
	assert.Equal(t, 100, result.(*RangeConstraint).Max, "Merged constraint should have max 100")

	// Test merging non-overlapping range constraints
	c1 = NewRangeConstraint("pid", 10, 20)
	c2 = NewRangeConstraint("pid", 30, 40)
	_, ok = c1.Merge(c2)

	assert.False(t, ok, "Should not be able to merge non-overlapping range constraints")

	// Test merging range with one-sided bound
	c1 = NewRangeConstraint("pid", 10, nil)
	c2 = NewRangeConstraint("pid", nil, 100)
	result, ok = c1.Merge(c2)

	assert.True(t, ok, "Should be able to merge one-sided range constraints")
	assert.Equal(t, 10, result.(*RangeConstraint).Min, "Merged constraint should have min 10")
	assert.Equal(t, 100, result.(*RangeConstraint).Max, "Merged constraint should have max 100")

	// Test merging range with equals constraint
	c1 = NewRangeConstraint("pid", 10, 100)
	eq := NewEqualsConstraint("pid", 50)
	result, ok = c1.Merge(eq)

	assert.True(t, ok, "Should be able to merge range with equals constraint inside range")
	assert.Equal(t, "equals", result.Type(), "Result should be an equals constraint")
	assert.Equal(t, 50, result.(*EqualsConstraint).Value, "Merged constraint should have value 50")

	// Test merging range with equals constraint outside range
	c1 = NewRangeConstraint("pid", 10, 100)
	eq = NewEqualsConstraint("pid", 150)
	_, ok = c1.Merge(eq)

	assert.False(t, ok, "Should not be able to merge range with equals constraint outside range")
}

func TestSetConstraintMerge(t *testing.T) {
	// Test merging set with equals constraint in set
	c1 := NewSetConstraint("container", []any{"a", "b", "c"})
	eq := NewEqualsConstraint("container", "b")
	result, ok := c1.Merge(eq)

	assert.True(t, ok, "Should be able to merge set with equals constraint in set")
	assert.Equal(t, "equals", result.Type(), "Result should be an equals constraint")
	assert.Equal(t, "b", result.(*EqualsConstraint).Value, "Merged constraint should have value 'b'")

	// Test merging set with equals constraint not in set
	c1 = NewSetConstraint("container", []any{"a", "b", "c"})
	eq = NewEqualsConstraint("container", "d")
	_, ok = c1.Merge(eq)

	assert.False(t, ok, "Should not be able to merge set with equals constraint not in set")

	// Test merging two sets with overlapping values
	c1 = NewSetConstraint("container", []any{"a", "b", "c"})
	c2 := NewSetConstraint("container", []any{"b", "c", "d"})
	result, ok = c1.Merge(c2)

	assert.True(t, ok, "Should be able to merge sets with overlapping values")
	assert.Equal(t, "set", result.Type(), "Result should be a set constraint")
	assert.Len(t, result.(*SetConstraint).Values, 2, "Merged set should have 2 values")

	// Test merging two sets with no overlapping values
	c1 = NewSetConstraint("container", []any{"a", "b"})
	c2 = NewSetConstraint("container", []any{"c", "d"})
	_, ok = c1.Merge(c2)

	assert.False(t, ok, "Should not be able to merge sets with no overlapping values")
}

func TestOffloadPatcherRegistration(t *testing.T) {
	// Create a new OffloadPatcher
	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}

	// Register offloaders
	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	// Test that offloaders were registered correctly
	assert.Len(t, op.offloaders, 2, "Should have 2 registered offloaders")
	assert.Len(t, op.offloaders["container"], 1, "Should have 1 container offloader")
	assert.Len(t, op.offloaders["pid"], 1, "Should have 1 pid offloader")

	// Test that offloader names are correct
	assert.Equal(t, "container", op.offloaders["container"][0].Name, "Container offloader should have name 'container'")
	assert.Equal(t, "pid", op.offloaders["pid"][0].Name, "PID offloader should have name 'pid'")
}
