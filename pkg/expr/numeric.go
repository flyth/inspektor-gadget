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

	"golang.org/x/exp/constraints"
)

// NumericValue is a constraint for any integer or floating-point type
type NumericValue interface {
	constraints.Integer | constraints.Float
}

// toFloat64 converts any numeric value to float64 for comparison
func toFloat64(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// compareNumeric compares two values of potentially different numeric types
func compareNumeric(a, b any) (int, error) {
	fa, okA := toFloat64(a)
	fb, okB := toFloat64(b)

	if !okA || !okB {
		return 0, fmt.Errorf("cannot compare non-numeric values: %T and %T", a, b)
	}

	switch {
	case fa < fb:
		return -1, nil
	case fa > fb:
		return 1, nil
	default:
		return 0, nil
	}
}

// isValueInRange checks if a value is within a range, handling nil min/max values
// and different numeric types
func isValueInRange(value, min, max any) bool {
	// If the value isn't numeric, we can't compare it
	valueFloat, ok := toFloat64(value)
	if !ok {
		return false
	}

	// Check min bound if present
	if min != nil {
		minFloat, ok := toFloat64(min)
		if ok && valueFloat < minFloat {
			return false
		}
	}

	// Check max bound if present
	if max != nil {
		maxFloat, ok := toFloat64(max)
		if ok && valueFloat > maxFloat {
			return false
		}
	}

	return true
}

// compareValues provides a generic comparison function for two values
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func compareValues[T constraints.Ordered](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
