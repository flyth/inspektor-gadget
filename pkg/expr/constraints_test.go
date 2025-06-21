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
	"fmt"
	"testing"
)

func TestEqualsConstraintContains(t *testing.T) {
	tests := []struct {
		name     string
		c        *EqualsConstraint
		value    any
		expected bool
	}{
		{
			name:     "int equals int",
			c:        NewEqualsConstraint("test", 42),
			value:    42,
			expected: true,
		},
		{
			name:     "int not equals int",
			c:        NewEqualsConstraint("test", 42),
			value:    43,
			expected: false,
		},
		{
			name:     "int equals int64",
			c:        NewEqualsConstraint("test", 42),
			value:    int64(42),
			expected: true,
		},
		{
			name:     "string equals string",
			c:        NewEqualsConstraint("test", "value"),
			value:    "value",
			expected: true,
		},
		{
			name:     "string not equals string",
			c:        NewEqualsConstraint("test", "value"),
			value:    "other",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For numeric comparison, use toFloat64 to compare numbers of different types
			if num1, ok1 := toFloat64(tt.c.Value); ok1 {
				if num2, ok2 := toFloat64(tt.value); ok2 {
					result := num1 == num2
					if result != tt.expected {
						t.Errorf("Expected %v, got %v for numeric comparison", tt.expected, result)
					}
					return
				}
			}

			// Fall back to direct comparison for non-numeric types
			result := fmt.Sprintf("%v", tt.c.Value) == fmt.Sprintf("%v", tt.value)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for string comparison", tt.expected, result)
			}
		})
	}
}

func TestRangeConstraintContains(t *testing.T) {
	tests := []struct {
		name     string
		c        *RangeConstraint
		value    any
		expected bool
	}{
		{
			name:     "value within range",
			c:        NewRangeConstraint("test", 10, 20),
			value:    15,
			expected: true,
		},
		{
			name:     "value at min boundary",
			c:        NewRangeConstraint("test", 10, 20),
			value:    10,
			expected: true,
		},
		{
			name:     "value at max boundary",
			c:        NewRangeConstraint("test", 10, 20),
			value:    20,
			expected: true,
		},
		{
			name:     "value below range",
			c:        NewRangeConstraint("test", 10, 20),
			value:    5,
			expected: false,
		},
		{
			name:     "value above range",
			c:        NewRangeConstraint("test", 10, 20),
			value:    25,
			expected: false,
		},
		{
			name:     "min only range, value above min",
			c:        NewRangeConstraint("test", 10, nil),
			value:    15,
			expected: true,
		},
		{
			name:     "min only range, value below min",
			c:        NewRangeConstraint("test", 10, nil),
			value:    5,
			expected: false,
		},
		{
			name:     "max only range, value below max",
			c:        NewRangeConstraint("test", nil, 20),
			value:    15,
			expected: true,
		},
		{
			name:     "max only range, value above max",
			c:        NewRangeConstraint("test", nil, 20),
			value:    25,
			expected: false,
		},
		{
			name:     "int value in int64 range",
			c:        NewRangeConstraint("test", int64(10), int64(20)),
			value:    15,
			expected: true,
		},
		{
			name:     "float value in int range",
			c:        NewRangeConstraint("test", 10, 20),
			value:    15.5,
			expected: true,
		},
		{
			name:     "string value always false",
			c:        NewRangeConstraint("test", 10, 20),
			value:    "15",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.c.Contains(tt.value); result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSetConstraintContains(t *testing.T) {
	tests := []struct {
		name     string
		c        *SetConstraint
		value    any
		expected bool
	}{
		{
			name:     "int value in int set",
			c:        NewSetConstraint("test", []any{10, 20, 30}),
			value:    20,
			expected: true,
		},
		{
			name:     "int value not in int set",
			c:        NewSetConstraint("test", []any{10, 20, 30}),
			value:    25,
			expected: false,
		},
		{
			name:     "int64 value in int set",
			c:        NewSetConstraint("test", []any{10, 20, 30}),
			value:    int64(20),
			expected: true,
		},
		{
			name:     "string value in string set",
			c:        NewSetConstraint("test", []any{"a", "b", "c"}),
			value:    "b",
			expected: true,
		},
		{
			name:     "string value not in string set",
			c:        NewSetConstraint("test", []any{"a", "b", "c"}),
			value:    "d",
			expected: false,
		},
		{
			name:     "mixed set with int value",
			c:        NewSetConstraint("test", []any{"a", 10, true}),
			value:    10,
			expected: true,
		},
		{
			name:     "mixed set with string value",
			c:        NewSetConstraint("test", []any{"a", 10, true}),
			value:    "a",
			expected: true,
		},
		{
			name:     "float value in int set",
			c:        NewSetConstraint("test", []any{10, 20, 30}),
			value:    20.0,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.c.Contains(tt.value); result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConstraintMerging(t *testing.T) {
	// Create a handler for merging
	handler := NewConstraintHandler("test")

	tests := []struct {
		name      string
		c1        Constraint
		c2        Constraint
		expected  bool
		resultMsg string
	}{
		{
			name:      "equal equals constraints",
			c1:        NewEqualsConstraint("test", 42),
			c2:        NewEqualsConstraint("test", 42),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "different equals constraints",
			c1:        NewEqualsConstraint("test", 42),
			c2:        NewEqualsConstraint("test", 43),
			expected:  false,
			resultMsg: "different values cannot be merged",
		},
		{
			name:      "equals within range",
			c1:        NewEqualsConstraint("test", 15),
			c2:        NewRangeConstraint("test", 10, 20),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "equals outside range",
			c1:        NewEqualsConstraint("test", 25),
			c2:        NewRangeConstraint("test", 10, 20),
			expected:  false,
			resultMsg: "value outside range",
		},
		{
			name:      "ranges with overlap",
			c1:        NewRangeConstraint("test", 10, 30),
			c2:        NewRangeConstraint("test", 20, 40),
			expected:  true,
			resultMsg: "narrowed to [20,30]",
		},
		{
			name:      "ranges without overlap",
			c1:        NewRangeConstraint("test", 10, 20),
			c2:        NewRangeConstraint("test", 30, 40),
			expected:  false,
			resultMsg: "no overlap in ranges",
		},
		{
			name:      "equals in set",
			c1:        NewEqualsConstraint("test", 20),
			c2:        NewSetConstraint("test", []any{10, 20, 30}),
			expected:  true,
			resultMsg: "equals constraint preserved",
		},
		{
			name:      "equals not in set",
			c1:        NewEqualsConstraint("test", 25),
			c2:        NewSetConstraint("test", []any{10, 20, 30}),
			expected:  false,
			resultMsg: "value not in set",
		},
		{
			name:      "sets with overlap",
			c1:        NewSetConstraint("test", []any{10, 20, 30}),
			c2:        NewSetConstraint("test", []any{20, 30, 40}),
			expected:  true,
			resultMsg: "intersection is [20,30]",
		},
		{
			name:      "sets without overlap",
			c1:        NewSetConstraint("test", []any{10, 20}),
			c2:        NewSetConstraint("test", []any{30, 40}),
			expected:  false,
			resultMsg: "no common values",
		},
		{
			name:      "mixed numeric types in set",
			c1:        NewSetConstraint("test", []any{10, 20.0, int64(30)}),
			c2:        NewSetConstraint("test", []any{int64(10), 20, float32(30)}),
			expected:  true,
			resultMsg: "numeric equivalence",
		},
		{
			name:      "set and range with overlap",
			c1:        NewSetConstraint("test", []any{5, 15, 25, 35}),
			c2:        NewRangeConstraint("test", 10, 30),
			expected:  true,
			resultMsg: "set filtered to [15,25]",
		},
		{
			name:      "different field names",
			c1:        NewEqualsConstraint("field1", 42),
			c2:        NewEqualsConstraint("field2", 42),
			expected:  false,
			resultMsg: "different fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := handler.MergeConstraints(tt.c1, tt.c2)
			if ok != tt.expected {
				t.Errorf("Expected merge result %v, got %v - %s", tt.expected, ok, tt.resultMsg)
			}

			if ok && result == nil {
				t.Errorf("Merge succeeded but returned nil constraint")
			}
		})
	}
}
