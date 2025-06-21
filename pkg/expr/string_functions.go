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

// StringFunctionConstraint represents a constraint using a string function like startsWith, endsWith, or contains
type StringFunctionConstraint struct {
	baseConstraint
	Function string // The function name: "startsWith", "endsWith", or "contains"
	Value    string // The string value to check against
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
			default:
				// For other constraint types, use the generic constraint handler
				return handler.CheckGenericConstraint(c)
			}
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *StringFunctionConstraint:
				// Implement the actual offloading logic for string functions
				// This would typically involve configuring an eBPF program

				// Example implementation:
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
