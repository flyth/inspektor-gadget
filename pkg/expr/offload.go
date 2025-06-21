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
	"log/slog"

	"github.com/expr-lang/expr/ast"
)

var comparisonOperators = map[string]bool{
	"==": true,
	"!=": true,
	">":  true,
	">=": true,
	"<":  true,
	"<=": true,
}

var logicalOperators = map[string]bool{
	"||": true,
	"&&": true,
}

// Constraint is an interface for filter constraints that can be offloaded
type Constraint interface {
	Name() string
	Type() string
	Merge(Constraint) (Constraint, bool)
}

type baseConstraint struct {
	name  string
	cType string
}

func (c *baseConstraint) Name() string {
	return c.name
}

func (c *baseConstraint) Type() string {
	return c.cType
}

// EqualsConstraint represents a constraint requiring an exact value match
type EqualsConstraint struct {
	baseConstraint
	Value any
}

// NewEqualsConstraint creates a new equals constraint with the given name and value
func NewEqualsConstraint(name string, value any) *EqualsConstraint {
	return &EqualsConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "equals",
		},
		Value: value,
	}
}

// Merge attempts to merge this constraint with another constraint
func (c *EqualsConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	switch o := other.(type) {
	case *EqualsConstraint:
		// Two equals with same value -> remains equals
		if fmt.Sprintf("%v", c.Value) == fmt.Sprintf("%v", o.Value) {
			return c, true
		}
		// Two different values -> not mergeable
		return nil, false
	case *RangeConstraint:
		// Check if the equals value is within the range
		if o.Contains(c.Value) {
			// Keep the more specific equals constraint
			return c, true
		}
		return nil, false
	case *SetConstraint:
		// Check if the equals value is in the set
		if o.Contains(c.Value) {
			// Keep the more specific equals constraint
			return c, true
		}
		return nil, false
	default:
		return nil, false
	}
}

// RangeConstraint represents a constraint with min and max bounds
type RangeConstraint struct {
	baseConstraint
	Min any
	Max any
}

// NewRangeConstraint creates a new range constraint with the given name, min, and max values
func NewRangeConstraint(name string, min, max any) *RangeConstraint {
	return &RangeConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "range",
		},
		Min: min,
		Max: max,
	}
}

// Contains checks if the given value is within this constraint's range
func (c *RangeConstraint) Contains(value any) bool {
	// Use the utility function that handles all numeric types
	return isValueInRange(value, c.Min, c.Max)
}

// Merge attempts to merge this constraint with another constraint
func (c *RangeConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	switch o := other.(type) {
	case *EqualsConstraint:
		// Check if the value is within the range
		if c.Contains(o.Value) {
			// Keep the more specific equals constraint
			return o, true
		}
		return nil, false

	case *RangeConstraint:
		// Initialize with existing bounds
		var newMin, newMax any = c.Min, c.Max

		// Handle min bound - we need the higher of the two min values
		if c.Min != nil && o.Min != nil {
			// Compare the two min values and use the higher one
			compResult, err := compareNumeric(c.Min, o.Min)
			if err == nil {
				if compResult > 0 { // c.Min > o.Min
					newMin = c.Min
				} else { // c.Min <= o.Min
					newMin = o.Min
				}
			}
		} else if o.Min != nil {
			// Only second constraint has min bound
			newMin = o.Min
		}

		// Handle max bound - we need the lower of the two max values
		if c.Max != nil && o.Max != nil {
			// Compare the two max values and use the lower one
			compResult, err := compareNumeric(c.Max, o.Max)
			if err == nil {
				if compResult < 0 { // c.Max < o.Max
					newMax = c.Max
				} else { // c.Max >= o.Max
					newMax = o.Max
				}
			}
		} else if o.Max != nil {
			// Only second constraint has max bound
			newMax = o.Max
		}

		// Check if the range is valid (min <= max)
		if newMin != nil && newMax != nil {
			// Compare min and max to ensure min <= max
			compResult, err := compareNumeric(newMin, newMax)
			if err != nil || compResult > 0 { // min > max
				return nil, false
			}
		}

		return NewRangeConstraint(c.Name(), newMin, newMax), true

	default:
		return nil, false
	}
}

// SetConstraint represents a constraint with a set of allowed values
type SetConstraint struct {
	baseConstraint
	Values []any
}

// NewSetConstraint creates a new set constraint with the given name and values
func NewSetConstraint(name string, values []any) *SetConstraint {
	return &SetConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "set",
		},
		Values: values,
	}
}

// Contains checks if the given value is in this constraint's set of values
func (c *SetConstraint) Contains(value any) bool {
	// First try direct equality check for efficiency
	for _, v := range c.Values {
		// For numeric values, try numeric comparison
		if n1, ok1 := toFloat64(value); ok1 {
			if n2, ok2 := toFloat64(v); ok2 {
				if n1 == n2 {
					return true
				}
				continue
			}
		}

		// For non-numeric values or if numeric comparison failed, use string comparison
		if fmt.Sprintf("%v", v) == fmt.Sprintf("%v", value) {
			return true
		}
	}
	return false
}

// Merge attempts to merge this constraint with another constraint
func (c *SetConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		return nil, false
	}

	switch o := other.(type) {
	case *EqualsConstraint:
		if c.Contains(o.Value) {
			return o, true
		}
		return nil, false

	case *SetConstraint:
		// Intersection of the two sets
		var newValues []any

		// Build a map for faster lookups
		lookupMap := make(map[string]any, len(o.Values))

		// Track numeric values separately for more accurate comparison
		numericValues := make(map[float64]any)

		// Add second set's values to lookup maps
		for _, v := range o.Values {
			// Add string representation
			lookupMap[fmt.Sprintf("%v", v)] = v

			// If numeric, add to numeric map
			if num, ok := toFloat64(v); ok {
				numericValues[num] = v
			}
		}

		// Check each value from first set against maps
		for _, v1 := range c.Values {
			// Check for numeric equality first (more accurate)
			if num, ok := toFloat64(v1); ok {
				if _, exists := numericValues[num]; exists {
					newValues = append(newValues, v1)
					continue
				}
			}

			// Fall back to string comparison
			if _, exists := lookupMap[fmt.Sprintf("%v", v1)]; exists {
				newValues = append(newValues, v1)
			}
		}

		if len(newValues) > 0 {
			return NewSetConstraint(c.Name(), newValues), true
		}

		return nil, false

	case *RangeConstraint:
		// Find values in the set that fall within the range
		var newValues []any
		for _, val := range c.Values {
			if o.Contains(val) {
				newValues = append(newValues, val)
			}
		}

		if len(newValues) > 0 {
			return NewSetConstraint(c.Name(), newValues), true
		}

		return nil, false

	default:
		return nil, false
	}
}

// OffloadInfo contains information about an offloader for a specific field
type OffloadInfo struct {
	Name            string
	CheckCallback   func(any) (bool, error)
	OffloadCallback func(context.Context, any) (bool, error)
}

// OffloadPatcher is responsible for patching the AST to offload filter operations
type OffloadPatcher struct {
	visited    map[*ast.Node]struct{}
	offloaders map[string][]*OffloadInfo
	activated  map[string]bool // Tracks which offloaders were activated
}

// NewOffloadPatcher creates a new OffloadPatcher with initialized maps
func NewOffloadPatcher() *OffloadPatcher {
	return &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
		activated:  make(map[string]bool),
	}
}

// nodeToString attempts to convert an AST node to a readable string representation for debugging
func nodeToString(node ast.Node) string {
	switch n := node.(type) {
	case *ast.BinaryNode:
		return fmt.Sprintf("%s %s %s", nodeToString(n.Left), n.Operator, nodeToString(n.Right))
	case *ast.UnaryNode:
		return fmt.Sprintf("%s%s", n.Operator, nodeToString(n.Node))
	case *ast.IdentifierNode:
		return n.Value
	case *ast.StringNode:
		return fmt.Sprintf("\"%s\"", n.Value)
	case *ast.IntegerNode:
		return fmt.Sprintf("%v", n.Value)
	case *ast.FloatNode:
		return fmt.Sprintf("%v", n.Value)
	case *ast.BoolNode:
		return fmt.Sprintf("%v", n.Value)
	case *ast.ConstantNode:
		return fmt.Sprintf("%v", n.Value)
	default:
		return fmt.Sprintf("<%T>", node)
	}
}

// CheckOffload checks if a constraint can be offloaded
func (o *OffloadPatcher) CheckOffload(ctx context.Context, name string, constraint any) (bool, error) {
	// Check if this field has any registered offloaders
	offloaders, exists := o.offloaders[name]
	if !exists || len(offloaders) == 0 {
		return false, nil
	}

	for _, offload := range offloaders {
		ok, err := offload.CheckCallback(constraint)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// ActivateOffload attempts to activate an offloader with the given constraint
func (o *OffloadPatcher) ActivateOffload(ctx context.Context, name string, constraint any) (bool, error) {
	for _, offload := range o.offloaders[name] {
		ok, err := offload.OffloadCallback(ctx, constraint)
		if err != nil {
			return false, err
		}
		if ok {
			o.activated[name] = true
			return true, nil
		}
	}
	return false, nil
}

// createConstraint creates a constraint based on the operator and value
func (o *OffloadPatcher) createConstraint(identifier string, operator string, value any) Constraint {
	switch operator {
	case "==":
		return NewEqualsConstraint(identifier, value)
	case "!=":
		// Not equals is harder to represent in kernel - usually not offloadable
		return nil
	case ">":
		// Create a range constraint with min=value+1, max=MAX_VALUE
		return NewRangeConstraint(identifier, value, nil)
	case ">=":
		// Create a range constraint with min=value, max=MAX_VALUE
		return NewRangeConstraint(identifier, value, nil)
	case "<":
		// Create a range constraint with min=MIN_VALUE, max=value-1
		return NewRangeConstraint(identifier, nil, value)
	case "<=":
		// Create a range constraint with min=MIN_VALUE, max=value
		return NewRangeConstraint(identifier, nil, value)
	default:
		return nil
	}
}

// IsOffloadable checks if a node can be offloaded
func (o *OffloadPatcher) IsOffloadable(ctx context.Context, node *ast.Node) (bool, Constraint) {
	o.visited[node] = struct{}{}

	// First check if it's a string function call
	if ok, constraint := o.CheckStringFunctionCall(ctx, node); ok {
		return true, constraint
	}

	switch nx := (*node).(type) {
	case *ast.BinaryNode:
		if comparisonOperators[nx.Operator] {
			var identifier *ast.IdentifierNode
			var other ast.Node
			var value any
			var operator string = nx.Operator
			var swapped bool

			// One side must be a constant
			if tmpIdentifier, ok := nx.Left.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Right
			} else if tmpIdentifier, ok := nx.Right.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Left
				swapped = true
			}

			if identifier == nil {
				return false, nil
			}

			// Extract the value
			switch on := other.(type) {
			case *ast.StringNode:
				value = on.Value
			case *ast.IntegerNode:
				value = on.Value
			case *ast.FloatNode:
				value = on.Value
			case *ast.BoolNode:
				value = on.Value
			default:
				return false, nil
			}

			// If the identifier was on the right side, we need to flip the operator
			if swapped {
				switch operator {
				case ">":
					operator = "<"
				case ">=":
					operator = "<="
				case "<":
					operator = ">"
				case "<=":
					operator = ">="
				}
			}

			// Create the appropriate constraint
			constraint := o.createConstraint(identifier.Value, operator, value)
			if constraint == nil {
				return false, nil
			}

			// Check if the constraint can be offloaded
			offloadable, err := o.CheckOffload(ctx, identifier.Value, constraint)
			if err != nil {
				return false, nil
			}

			return offloadable, constraint
		}

		if logicalOperators[nx.Operator] {
			ok1, c1 := o.IsOffloadable(ctx, &nx.Left)
			ok2, c2 := o.IsOffloadable(ctx, &nx.Right)

			// Handle OR operation
			if nx.Operator == "||" {
				// For traditional OR offloading (same field on both sides)
				if ok1 && ok2 && c1.Name() == c2.Name() {
					// For OR operations with same field, we can create a set constraint
					if c1.Type() == "equals" && c2.Type() == "equals" {
						eq1 := c1.(*EqualsConstraint)
						eq2 := c2.(*EqualsConstraint)
						setConstraint := NewSetConstraint(c1.Name(), []any{eq1.Value, eq2.Value})
						return true, setConstraint
					}

					// Handle OR of range constraints specifically for pid field
					if c1.Type() == "range" && c2.Type() == "range" && c1.Name() == "pid" {
						r1 := c1.(*RangeConstraint)
						r2 := c2.(*RangeConstraint)

						// Create a special "multi-range" constraint that can be handled by the PID offloader
						specialConstraint := &RangeConstraint{
							baseConstraint: baseConstraint{
								name:  "pid",
								cType: "multi-range", // Special type to identify this case
							},
							// Store both ranges as a map in Min to be retrieved later
							Min: map[string]any{
								"range1": map[string]any{"min": r1.Min, "max": r1.Max},
								"range2": map[string]any{"min": r2.Min, "max": r2.Max},
							},
							Max: nil,
						}

						return true, specialConstraint
					}

					// ORing ranges for other fields isn't generally offloadable unless they overlap significantly
					return false, nil
				}

				// Handle partial OR offloading where only one side is offloadable
				if ok1 && !ok2 {
					// Return the constraint from the offloadable side
					return true, c1
				}

				if !ok1 && ok2 {
					// Return the constraint from the offloadable side
					return true, c2
				}

				// If we get here, neither side is offloadable
				return false, nil
			}

			// Handle AND operation
			if nx.Operator == "&&" {
				// If either side isn't offloadable, the whole thing isn't
				if !ok1 || !ok2 {
					return false, nil
				}

				// If constraints apply to different fields, both can be offloaded
				if c1.Name() != c2.Name() {
					// This is a simplified approach - in reality, you'd need to track both constraints
					// and apply them at the offloading phase
					return true, c1 // Just return one of them for now
				}

				// For the same field, try to merge the constraints using our helper
				handler := NewConstraintHandler("merger")
				mergedConstraint, canMerge := handler.MergeConstraints(c1, c2)

				if canMerge {
					return true, mergedConstraint
				}

				// Constraints are incompatible (e.g., x > 10 && x < 5)
				return false, nil
			}
		}

		return false, nil

	case *ast.UnaryNode:
		// Handle NOT operations if needed
		if nx.Operator == "!" {
			// NOT operations are typically harder to offload
			return false, nil
		}
		return o.IsOffloadable(ctx, &nx.Node)

	default:
		return false, nil
	}
}

// RegisterOffloader registers an offloader for a specific field
func (o *OffloadPatcher) RegisterOffloader(name string, oi *OffloadInfo) {
	o.offloaders[name] = append(o.offloaders[name], oi)
}

// Visit implements the ast.Visitor interface
func (o *OffloadPatcher) Visit(node *ast.Node) {
	// Use background context if none provided
	ctx := context.Background()
	if _, ok := o.visited[node]; ok {
		return
	}

	if ok, constraint := o.IsOffloadable(ctx, node); ok {
		slog.LogAttrs(ctx, slog.LevelInfo, "Offloading node",
			slog.String("field", constraint.Name()),
			slog.Any("constraint", constraint))

		// Special handling for OR nodes where only one side is offloadable
		if nx, isOr := (*node).(*ast.BinaryNode); isOr && nx.Operator == "||" {
			ok1, c1 := o.IsOffloadable(ctx, &nx.Left)
			ok2, c2 := o.IsOffloadable(ctx, &nx.Right)

			// If only one side is offloadable, we need to handle specially
			if (ok1 && !ok2) || (!ok1 && ok2) {
				var partialConstraint Constraint
				var sideToActivate string

				if ok1 {
					partialConstraint = c1
					sideToActivate = "left"
				} else {
					partialConstraint = c2
					sideToActivate = "right"
				}

				// Activate the offloader for the constraint
				activated, err := o.ActivateOffload(ctx, partialConstraint.Name(), partialConstraint)
				if err != nil {
					return
				}

				if activated {
					// For OR with one side offloadable, we patch that side to 'true'
					// but leave the OR operation in place
					if sideToActivate == "left" {
						ast.Patch(&nx.Left, &ast.ConstantNode{Value: true})
					} else {
						ast.Patch(&nx.Right, &ast.ConstantNode{Value: true})
					}
					return
				}
			}
		}

		// Special handling for AND nodes with different field constraints
		if nx, isAnd := (*node).(*ast.BinaryNode); isAnd && nx.Operator == "&&" {
			// Check if this AND has two different field constraints
			ok1, c1 := o.IsOffloadable(ctx, &nx.Left)
			ok2, c2 := o.IsOffloadable(ctx, &nx.Right)

			if ok1 && ok2 && c1.Name() != c2.Name() {
				// Activate both offloaders
				activated1, err1 := o.ActivateOffload(ctx, c1.Name(), c1)
				activated2, err2 := o.ActivateOffload(ctx, c2.Name(), c2)

				if err1 != nil || err2 != nil {
					return
				}

				if activated1 && activated2 {
					// Replace the node with a constant true
					ast.Patch(node, &ast.ConstantNode{Value: true})
					return
				}
			}
		}

		// For standard (non-OR, non-AND) offloadable nodes
		activated, err := o.ActivateOffload(ctx, constraint.Name(), constraint)
		if err != nil {
			return
		}

		if activated {
			// Replace the node with a constant true since this part will be handled in the kernel
			ast.Patch(node, &ast.ConstantNode{Value: true})
		}
	}
}
