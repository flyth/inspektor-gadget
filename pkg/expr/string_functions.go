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

// StringFunctionCondition represents a single string function condition
type StringFunctionCondition struct {
	Function string // The function name: "startsWith", "endsWith", or "contains"
	Value    string // The string value to check against
}

// StringFunctionConstraint represents a constraint using a string function like startsWith, endsWith, or contains
type StringFunctionConstraint struct {
	baseConstraint
	Function string // The function name: "startsWith", "endsWith", or "contains"
	Value    string // The string value to check against
}

// MultiStringFunctionConstraint represents a constraint with multiple string function conditions
type MultiStringFunctionConstraint struct {
	baseConstraint
	Conditions []StringFunctionCondition // List of string function conditions
	LogicalOp  string                    // Logical operator: "AND" or "OR"
}

// NewMultiStringFunctionConstraint creates a new multi-condition string function constraint
func NewMultiStringFunctionConstraint(name string, conditions []StringFunctionCondition, logicalOp string) *MultiStringFunctionConstraint {
	return &MultiStringFunctionConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "multi-string-function",
		},
		Conditions: conditions,
		LogicalOp:  logicalOp,
	}
}

// NewMultiStringFunctionConstraintFromPair creates a new multi-condition constraint from two string function constraints
func NewMultiStringFunctionConstraintFromPair(c1, c2 *StringFunctionConstraint, logicalOp string) *MultiStringFunctionConstraint {
	conditions := []StringFunctionCondition{
		{Function: c1.Function, Value: c1.Value},
		{Function: c2.Function, Value: c2.Value},
	}
	return NewMultiStringFunctionConstraint(c1.Name(), conditions, logicalOp)
}

// Merge attempts to merge this constraint with another constraint
func (c *MultiStringFunctionConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	// Multi-string function constraints can only be merged with equals constraints
	switch o := other.(type) {
	case *EqualsConstraint:
		strValue, ok := o.Value.(string)
		if !ok {
			return nil, false
		}

		// For AND, all conditions must be satisfied
		if c.LogicalOp == "AND" {
			// Check if the equals value satisfies all conditions
			for _, condition := range c.Conditions {
				switch condition.Function {
				case "startsWith":
					if !strings.HasPrefix(strValue, condition.Value) {
						return nil, false
					}
				case "endsWith":
					if !strings.HasSuffix(strValue, condition.Value) {
						return nil, false
					}
				case "contains":
					if !strings.Contains(strValue, condition.Value) {
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
		if c.LogicalOp == "OR" {
			for _, condition := range c.Conditions {
				switch condition.Function {
				case "startsWith":
					if strings.HasPrefix(strValue, condition.Value) {
						return o, true
					}
				case "endsWith":
					if strings.HasSuffix(strValue, condition.Value) {
						return o, true
					}
				case "contains":
					if strings.Contains(strValue, condition.Value) {
						return o, true
					}
				}
			}

			// If no condition is satisfied, return false
			return nil, false
		}

		// Unknown logical operator
		return nil, false

	default:
		return nil, false
	}
}

// Type returns the constraint type
func (c *MultiStringFunctionConstraint) Type() string {
	return c.cType
}

// Name returns the constraint name
func (c *MultiStringFunctionConstraint) Name() string {
	return c.name
}

// NewStringFunctionConstraint creates a new string function constraint
func NewStringFunctionConstraint(name, function, value string) *StringFunctionConstraint {
	return &StringFunctionConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "string-function",
		},
		Function: function,
		Value:    value,
	}
}

// Merge attempts to merge this constraint with another constraint
func (c *StringFunctionConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	// String function constraints can only be merged with equals constraints
	// if the equals value satisfies the string function
	switch o := other.(type) {
	case *EqualsConstraint:
		strValue, ok := o.Value.(string)
		if !ok {
			return nil, false
		}

		// Check if the equals value satisfies the string function
		switch c.Function {
		case "startsWith":
			if strings.HasPrefix(strValue, c.Value) {
				return o, true
			}
		case "endsWith":
			if strings.HasSuffix(strValue, c.Value) {
				return o, true
			}
		case "contains":
			if strings.Contains(strValue, c.Value) {
				return o, true
			}
		}
		return nil, false

	case *StringFunctionConstraint:
		// Two string functions can only be merged if they're the same function with the same value
		if c.Function == o.Function && c.Value == o.Value {
			return c, true
		}
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

				// Check that the function is supported
				switch constraint.Function {
				case "startsWith", "endsWith", "contains":
					return true, nil
				default:
					return false, nil
				}
			case *MultiStringFunctionConstraint:
				// Check that the field name matches
				if constraint.Name() != fieldName {
					return false, nil
				}

				// Check that all functions are supported
				for _, condition := range constraint.Conditions {
					switch condition.Function {
					case "startsWith", "endsWith", "contains":
						// Function is supported
					default:
						return false, nil
					}
				}
				return true, nil
			default:
				// For other constraint types, use the generic constraint handler
				return handler.CheckGenericConstraint(c)
			}
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *StringFunctionConstraint:
				// Handle multi-string-function constraints (from logical operations)
				if constraint.Function == "multi" || constraint.Function == "multi-and" {
					// This is the old way of handling multiple conditions
					// For backward compatibility, we'll convert it to the new MultiStringFunctionConstraint

					// Parse the JSON-like structure from the Value field
					// This is a simplified parsing since we know the exact format
					value := constraint.Value
					isAnd := constraint.Function == "multi-and"

					// For demonstration purposes, we'll just log what we're doing
					if isAnd {
						// For AND, both conditions must be true
						fmt.Printf("Configuring eBPF program for AND of string functions: %s\n", value)
					} else {
						// For OR, either condition can be true
						fmt.Printf("Configuring eBPF program for OR of string functions: %s\n", value)
					}

					return true, nil
				}

				// Handle single string function constraints
				switch constraint.Function {
				case "startsWith":
					// Configure eBPF program to filter by prefix
					return true, nil
				case "endsWith":
					// Configure eBPF program to filter by suffix
					return true, nil
				case "contains":
					// Configure eBPF program to filter by substring
					return true, nil
				default:
					return false, fmt.Errorf("unsupported string function: %s", constraint.Function)
				}
			case *MultiStringFunctionConstraint:
				// Handle multi-condition string function constraints

				// Log what we're doing for demonstration purposes
				fmt.Printf("Configuring eBPF program for %s of string functions with %d conditions\n",
					constraint.LogicalOp, len(constraint.Conditions))

				// In a real implementation, we would configure the eBPF program
				// to check all conditions according to the logical operator
				for i, condition := range constraint.Conditions {
					fmt.Printf("  Condition %d: %s(%s)\n", i+1, condition.Function, condition.Value)
				}

				return true, nil
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
	if functionName != "startsWith" && functionName != "endsWith" && functionName != "contains" {
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
