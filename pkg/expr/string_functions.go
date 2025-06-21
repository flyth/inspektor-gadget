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
	"fmt"
	"strings"

	"github.com/expr-lang/expr/ast"
)

// String function constraint types
const (
	ConstraintTypeStringFunction = "string-function"
)

// String function names
const (
	FunctionStartsWith = "startsWith"
	FunctionEndsWith   = "endsWith"
	FunctionContains   = "contains"
	FunctionEquals     = "equals"
)

// Logical operators
const (
	LogicalOperatorAND = "AND"
	LogicalOperatorOR  = "OR"
)

// StringFunctionCondition represents a single string function condition
type StringFunctionCondition struct {
	Function string // The function name: FunctionStartsWith, FunctionEndsWith, FunctionContains, or FunctionEquals
	Value    string // The string value to check against
}

// StringFunctionConstraint represents a constraint using string functions
type StringFunctionConstraint struct {
	baseConstraint
	// For backward compatibility with existing code
	Function string // The function name for single condition: FunctionStartsWith, FunctionEndsWith, FunctionContains
	Value    string // The string value to check against for single condition

	// For multiple conditions
	Conditions []StringFunctionCondition // List of string function conditions
	LogicalOp  string                    // Logical operator: LogicalOperatorAND or LogicalOperatorOR
}

// NewStringFunctionConstraint creates a new string function constraint with a single condition
func NewStringFunctionConstraint(name, function, value string) *StringFunctionConstraint {
	return &StringFunctionConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: ConstraintTypeStringFunction,
		},
		Function: function,
		Value:    value,
		Conditions: []StringFunctionCondition{
			{Function: function, Value: value},
		},
		LogicalOp: LogicalOperatorAND, // Default to AND for single condition
	}
}

// NewMultiStringFunctionConstraint creates a new string function constraint with multiple conditions
func NewMultiStringFunctionConstraint(name string, conditions []StringFunctionCondition, logicalOp string) *StringFunctionConstraint {
	// For backward compatibility, set Function and Value from the first condition if available
	var function, value string
	if len(conditions) > 0 {
		function = conditions[0].Function
		value = conditions[0].Value
	}

	return &StringFunctionConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: ConstraintTypeStringFunction,
		},
		Function:   function,
		Value:      value,
		Conditions: conditions,
		LogicalOp:  logicalOp,
	}
}

// NewMultiStringFunctionConstraintFromPair creates a new multi-condition constraint from two string function constraints
func NewMultiStringFunctionConstraintFromPair(c1, c2 *StringFunctionConstraint, logicalOp string) *StringFunctionConstraint {
	conditions := make([]StringFunctionCondition, 0, len(c1.Conditions)+len(c2.Conditions))

	// Add conditions from first constraint
	conditions = append(conditions, c1.Conditions...)

	// Add conditions from second constraint
	conditions = append(conditions, c2.Conditions...)

	return NewMultiStringFunctionConstraint(c1.Name(), conditions, logicalOp)
}

// Merge attempts to merge this constraint with another constraint
func (c *StringFunctionConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	// String function constraints can be merged with equals constraints
	// if the equals value satisfies the string function conditions
	switch o := other.(type) {
	case *EqualsConstraint:
		strValue, ok := o.Value.(string)
		if !ok {
			return nil, false
		}

		// For AND, all conditions must be satisfied
		if c.LogicalOp == LogicalOperatorAND {
			// Check if the equals value satisfies all conditions
			for _, condition := range c.Conditions {
				switch condition.Function {
				case FunctionStartsWith:
					if !strings.HasPrefix(strValue, condition.Value) {
						return nil, false
					}
				case FunctionEndsWith:
					if !strings.HasSuffix(strValue, condition.Value) {
						return nil, false
					}
				case FunctionContains:
					if !strings.Contains(strValue, condition.Value) {
						return nil, false
					}
				case FunctionEquals:
					if strValue != condition.Value {
						return nil, false
					}
				default:
					return nil, false
				}
			}

			// If all conditions are satisfied, return the equals constraint
			return o, true
		}

		// For OR, at least one condition must be satisfied
		if c.LogicalOp == LogicalOperatorOR {
			for _, condition := range c.Conditions {
				switch condition.Function {
				case FunctionStartsWith:
					if strings.HasPrefix(strValue, condition.Value) {
						return o, true
					}
				case FunctionEndsWith:
					if strings.HasSuffix(strValue, condition.Value) {
						return o, true
					}
				case FunctionContains:
					if strings.Contains(strValue, condition.Value) {
						return o, true
					}
				case FunctionEquals:
					if strValue == condition.Value {
						return o, true
					}
				}
			}

			// If no condition is satisfied, return false
			return nil, false
		}

		// Unknown logical operator
		return nil, false

	case *StringFunctionConstraint:
		// If both constraints have the same conditions, they can be merged
		if len(c.Conditions) == len(o.Conditions) && c.LogicalOp == o.LogicalOp {
			// Check if all conditions match
			match := true
			for i, condition := range c.Conditions {
				if condition.Function != o.Conditions[i].Function || condition.Value != o.Conditions[i].Value {
					match = false
					break
				}
			}
			if match {
				return c, true
			}
		}

		// Otherwise, we can't merge them directly
		return nil, false

	default:
		return nil, false
	}
}

// StringFunctionOffloader creates an offloader for string function constraints
func StringFunctionOffloader(fieldName string) *OffloadInfo {
	handler := NewConstraintHandler(fieldName).WithMaxSetSize(10)

	return &OffloadInfo{
		Name: fieldName,
		CheckCallback: func(c any) (bool, error) {
			switch constraint := c.(type) {
			case *StringFunctionConstraint:
				// Check that the field name matches
				if constraint.Name() != fieldName {
					return false, nil
				}

				// If we have multiple conditions, check that all functions are supported
				if len(constraint.Conditions) > 0 {
					for _, condition := range constraint.Conditions {
						switch condition.Function {
						case FunctionStartsWith, FunctionEndsWith, FunctionContains, FunctionEquals:
							// Function is supported
						default:
							return false, nil
						}
					}
					return true, nil
				}

				// For backward compatibility, check the single condition
				switch constraint.Function {
				case FunctionStartsWith, FunctionEndsWith, FunctionContains, FunctionEquals:
					return true, nil
				default:
					return false, nil
				}
			default:
				// For other constraint types, use the generic constraint handler
				return handler.CheckGenericConstraint(c)
			}
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *StringFunctionConstraint:
				// Handle string function constraints with multiple conditions
				if len(constraint.Conditions) > 1 {
					// Log what we're doing for demonstration purposes
					fmt.Printf("Configuring eBPF program for %s of string functions with %d conditions\n",
						constraint.LogicalOp, len(constraint.Conditions))

					// In a real implementation, we would configure the eBPF program
					// to check all conditions according to the logical operator
					for i, condition := range constraint.Conditions {
						fmt.Printf("  Condition %d: %s(%s)\n", i+1, condition.Function, condition.Value)
					}

					return true, nil
				}

				// Handle single string function constraints
				switch constraint.Function {
				case FunctionStartsWith:
					// Configure eBPF program to filter by prefix
					return true, nil
				case FunctionEndsWith:
					// Configure eBPF program to filter by suffix
					return true, nil
				case FunctionContains:
					// Configure eBPF program to filter by substring
					return true, nil
				case FunctionEquals:
					// Configure eBPF program to filter by exact match
					return true, nil
				default:
					return false, fmt.Errorf("unsupported string function: %s", constraint.Function)
				}
			case *EqualsConstraint:
				// For equals constraints, use the string-specific helper
				return handler.ActivateStringEqualsConstraint(ctx, constraint,
					func(ctx context.Context, value string) (bool, error) {
						// Actual eBPF program configuration would happen here
						return true, nil
					})
			default:
				return false, fmt.Errorf("unsupported constraint type for string function offload: %T", c)
			}
		},
	}
}

// isStringFunctionCall checks if a node is a call to a string function like startsWith, endsWith, or contains
func isStringFunctionCall(node ast.Node) (bool, string, string, string) {
	callNode, ok := node.(*ast.CallNode)
	if !ok {
		return false, "", "", ""
	}

	// Check if it's a member call (e.g., field.startsWith("prefix"))
	memberNode, ok := callNode.Callee.(*ast.MemberNode)
	if !ok {
		return false, "", "", ""
	}

	// Get the field name
	identNode, ok := memberNode.Node.(*ast.IdentifierNode)
	if !ok {
		return false, "", "", ""
	}
	fieldName := identNode.Value

	// Get the function name - can be either an IdentifierNode or a StringNode
	var functionName string
	if propNode, ok := memberNode.Property.(*ast.IdentifierNode); ok {
		functionName = propNode.Value
	} else if propNode, ok := memberNode.Property.(*ast.StringNode); ok {
		functionName = propNode.Value
	} else {
		return false, "", "", ""
	}

	// Check if it's one of our supported string functions
	if functionName != FunctionStartsWith && functionName != FunctionEndsWith && functionName != FunctionContains {
		return false, "", "", ""
	}

	// Check if there's exactly one argument and it's a string
	if len(callNode.Arguments) != 1 {
		return false, "", "", ""
	}

	stringNode, ok := callNode.Arguments[0].(*ast.StringNode)
	if !ok {
		return false, "", "", ""
	}

	return true, fieldName, functionName, stringNode.Value
}

// CheckStringFunctionCall checks if a node is a string function call and creates a constraint if it is
func (o *OffloadPatcher) CheckStringFunctionCall(ctx context.Context, node *ast.Node) (bool, Constraint) {
	// Check if it's a string function call
	if isFunc, fieldName, functionName, value := isStringFunctionCall(*node); isFunc {
		// Create a string function constraint
		constraint := NewStringFunctionConstraint(fieldName, functionName, value)

		// Check if the constraint can be offloaded
		offloadable, err := o.CheckOffload(ctx, fieldName, constraint)
		if err != nil {
			return false, nil
		}

		return offloadable, constraint
	}

	return false, nil
}
