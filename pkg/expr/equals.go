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
)

// Contains checks if the given value equals this constraint's value
func (c *EqualsConstraint) Contains(value any) bool {
	// First try numeric comparison for efficiency and accuracy
	if n1, ok1 := toFloat64(c.Value); ok1 {
		if n2, ok2 := toFloat64(value); ok2 {
			return n1 == n2
		}
	}

	// Fall back to string comparison for non-numeric types
	return fmt.Sprintf("%v", c.Value) == fmt.Sprintf("%v", value)
}
