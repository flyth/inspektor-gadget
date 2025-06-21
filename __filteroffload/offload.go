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
	"fmt"

	"github.com/expr-lang/expr/ast"
	log "github.com/sirupsen/logrus"
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

func NewEqualsConstraint(name string, value any) *EqualsConstraint {
	return &EqualsConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "equals",
		},
		Value: value,
	}
}

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

func (c *RangeConstraint) Contains(value any) bool {
	// This is a simplified check - in a real implementation, you'd need
	// to handle different types (int, float, string) properly
	switch v := value.(type) {
	case int64:
		min, ok1 := c.Min.(int64)
		max, ok2 := c.Max.(int64)
		if ok1 && ok2 {
			return v >= min && v <= max
		}
		// Add other type cases as needed
	}
	return false
}

func (c *RangeConstraint) Merge(other Constraint) (Constraint, bool) {
	if c.Name() != other.Name() {
		log.Printf("❌ MERGE FAILED: Different field names: %s vs %s", c.Name(), other.Name())
		return nil, false
	}

	switch o := other.(type) {
	case *EqualsConstraint:
		log.Printf("ATTEMPTING to merge Range with Equals constraint for %s", c.Name())
		if c.Contains(o.Value) {
			// Keep the more specific equals constraint
			log.Printf("✅ MERGE SUCCESS: Equals value %v is within range [%v,%v] - keeping equals constraint",
				o.Value, c.Min, c.Max)
			return o, true
		}
		log.Printf("❌ MERGE FAILED: Equals value %v is outside range [%v,%v]",
			o.Value, c.Min, c.Max)
		return nil, false
	case *RangeConstraint:
		log.Printf("ATTEMPTING to merge two Range constraints for %s", c.Name())
		// We need to narrow the range to the intersection
		// Handle the special case where one range has nil bounds

		// Initialize with existing bounds
		var newMin, newMax any = c.Min, c.Max

		// Handle min bound from both constraints
		if c.Min != nil && o.Min != nil {
			// Both constraints have min bound - use the higher one
			switch min1 := c.Min.(type) {
			case int64:
				if min2, ok := o.Min.(int64); ok {
					if min1 > min2 {
						newMin = min1
						log.Printf("Using higher min value: %v (from first constraint)", min1)
					} else {
						newMin = min2
						log.Printf("Using higher min value: %v (from second constraint)", min2)
					}
				}
			case int:
				if min2, ok := o.Min.(int); ok {
					if min1 > min2 {
						newMin = min1
						log.Printf("Using higher min value: %v (from first constraint)", min1)
					} else {
						newMin = min2
						log.Printf("Using higher min value: %v (from second constraint)", min2)
					}
				}
			}
		} else if o.Min != nil {
			// Only second constraint has min bound
			newMin = o.Min
			log.Printf("Using min value: %v (from second constraint)", o.Min)
		}
		// c.Min is already assigned to newMin by default if neither condition matches

		// Handle max bound from both constraints
		if c.Max != nil && o.Max != nil {
			// Both constraints have max bound - use the lower one
			switch max1 := c.Max.(type) {
			case int64:
				if max2, ok := o.Max.(int64); ok {
					if max1 < max2 {
						newMax = max1
						log.Printf("Using lower max value: %v (from first constraint)", max1)
					} else {
						newMax = max2
						log.Printf("Using lower max value: %v (from second constraint)", max2)
					}
				}
			case int:
				if max2, ok := o.Max.(int); ok {
					if max1 < max2 {
						newMax = max1
						log.Printf("Using lower max value: %v (from first constraint)", max1)
					} else {
						newMax = max2
						log.Printf("Using lower max value: %v (from second constraint)", max2)
					}
				}
			}
		} else if o.Max != nil {
			// Only second constraint has max bound
			newMax = o.Max
			log.Printf("Using max value: %v (from second constraint)", o.Max)
		}
		// c.Max is already assigned to newMax by default if neither condition matches

		// Check if the range is valid (min <= max)
		if newMin != nil && newMax != nil {
			// Both bounds are set, check if range is valid
			valid := false

			// Handle different numeric types for bounds
			switch min := newMin.(type) {
			case int64:
				if max, ok := newMax.(int64); ok {
					if min <= max {
						valid = true
					} else {
						log.Printf("❌ MERGE FAILED: Resulting range [%v,%v] is invalid (min > max)", min, max)
					}
				}
			case int:
				switch max := newMax.(type) {
				case int:
					if min <= max {
						valid = true
					} else {
						log.Printf("❌ MERGE FAILED: Resulting range [%v,%v] is invalid (min > max)", min, max)
					}
				case int64:
					if int64(min) <= max {
						valid = true
					} else {
						log.Printf("❌ MERGE FAILED: Resulting range [%v,%v] is invalid (min > max)", min, max)
					}
				}
			}

			if !valid {
				return nil, false
			}
		}

		log.Printf("✅ MERGE SUCCESS: Created new range constraint [%v,%v]", newMin, newMax)
		return NewRangeConstraint(c.Name(), newMin, newMax), true
	default:
		log.Printf("❌ MERGE FAILED: Unsupported constraint type %T", other)
		return nil, false
	}
}

// SetConstraint represents a constraint with a set of allowed values
type SetConstraint struct {
	baseConstraint
	Values []any
}

func NewSetConstraint(name string, values []any) *SetConstraint {
	return &SetConstraint{
		baseConstraint: baseConstraint{
			name:  name,
			cType: "set",
		},
		Values: values,
	}
}

func (c *SetConstraint) Contains(value any) bool {
	valStr := fmt.Sprintf("%v", value)
	for _, v := range c.Values {
		if fmt.Sprintf("%v", v) == valStr {
			return true
		}
	}
	return false
}

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
		for _, v1 := range c.Values {
			v1Str := fmt.Sprintf("%v", v1)
			for _, v2 := range o.Values {
				if fmt.Sprintf("%v", v2) == v1Str {
					newValues = append(newValues, v1)
					break
				}
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

type OffloadInfo struct {
	Name            string
	CheckCallback   func(any) (bool, error)
	OffloadCallback func(any) (bool, error)
}

type OffloadPatcher struct {
	visited    map[*ast.Node]struct{}
	offloaders map[string][]*OffloadInfo
	activated  map[string]bool // Tracks which offloaders were activated
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

func (o *OffloadPatcher) CheckOffload(name string, constraint any) (bool, error) {
	log.Printf("CHECKING offload capability for %q constraint: %+v", name, constraint)

	// Check if this field has any registered offloaders
	offloaders, exists := o.offloaders[name]
	if !exists || len(offloaders) == 0 {
		log.Printf("❌ No offloaders registered for field '%s'", name)
		return false, nil
	}

	for i, offload := range offloaders {
		log.Printf("  Trying offloader %d for %s: %s", i, name, offload.Name)
		ok, err := offload.CheckCallback(constraint)
		if err != nil {
			log.Printf("❌ Offloader %s returned error: %v", offload.Name, err)
			return false, err
		}
		if ok {
			log.Printf("✅ Offloader %s can handle constraint", offload.Name)
			return true, nil
		}
	}

	log.Printf("❌ No capable offloaders found for %s", name)
	return false, nil
}

// ActivateOffload attempts to activate an offloader with the given constraint
func (o *OffloadPatcher) ActivateOffload(name string, constraint any) (bool, error) {
	for _, offload := range o.offloaders[name] {
		ok, err := offload.OffloadCallback(constraint)
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

func (o *OffloadPatcher) IsOffloadable(node *ast.Node) (bool, Constraint) {
	o.visited[node] = struct{}{}

	// Helper function to log offloading failure reasons
	logOffloadFailure := func(nodeType string, reason string, details ...interface{}) {
		if len(details) > 0 {
			log.Printf("OFFLOAD FAILED for %s: %s - %v", nodeType, reason, details)
		} else {
			log.Printf("OFFLOAD FAILED for %s: %s", nodeType, reason)
		}
	}

	switch nx := (*node).(type) {
	case *ast.BinaryNode:
		log.Printf("CHECKING node: %T [%s]", nx, nx.Operator)

		if comparisonOperators[nx.Operator] {
			log.Printf("PROCESSING comparison operation: %s", nx.Operator)
			var identifier *ast.IdentifierNode
			var other ast.Node
			var value any
			var operator string = nx.Operator
			var swapped bool

			// One side must be a constant
			if tmpIdentifier, ok := nx.Left.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Right
				log.Printf("IDENTIFIED left-side identifier: %s", identifier.Value)
			} else if tmpIdentifier, ok := nx.Right.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Left
				swapped = true
				log.Printf("IDENTIFIED right-side identifier: %s", identifier.Value)
			}

			if identifier == nil {
				logOffloadFailure("BinaryNode", "no identifier found in comparison operation")
				return false, nil
			}

			// Extract the value
			switch on := other.(type) {
			case *ast.StringNode:
				value = on.Value
				log.Printf("EXTRACTED string value: %v", value)
			case *ast.IntegerNode:
				value = on.Value
				log.Printf("EXTRACTED integer value: %v", value)
			case *ast.FloatNode:
				value = on.Value
				log.Printf("EXTRACTED float value: %v", value)
			case *ast.BoolNode:
				value = on.Value
				log.Printf("EXTRACTED bool value: %v", value)
			default:
				logOffloadFailure("BinaryNode", "unsupported value type", other)
				return false, nil
			}

			// If the identifier was on the right side, we need to flip the operator
			if swapped {
				oldOp := operator
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
				log.Printf("SWAPPED operator due to right-side identifier: %s → %s", oldOp, operator)
			}

			// Create the appropriate constraint
			constraint := o.createConstraint(identifier.Value, operator, value)
			if constraint == nil {
				logOffloadFailure("BinaryNode", "unsupported operator for offloading", operator)
				return false, nil
			}

			log.Printf("CREATED constraint: %s[%s] with operator %s", constraint.Name(), constraint.Type(), operator)

			// Check if the constraint can be offloaded
			offloadable, err := o.CheckOffload(identifier.Value, constraint)
			if err != nil {
				logOffloadFailure("BinaryNode", "error checking offload", err)
				return false, nil
			}

			if !offloadable {
				logOffloadFailure("BinaryNode", "constraint not supported by any offloader", constraint)
			}

			return offloadable, constraint
		}

		if logicalOperators[nx.Operator] {
			log.Printf("PROCESSING logical operation: %s", nx.Operator)

			ok1, c1 := o.IsOffloadable(&nx.Left)
			ok2, c2 := o.IsOffloadable(&nx.Right)

			// Log the results of checking both sides
			if ok1 {
				log.Printf("LEFT side IS offloadable: %s[%s]", c1.Name(), c1.Type())
			} else {
				log.Printf("LEFT side is NOT offloadable")
			}

			if ok2 {
				log.Printf("RIGHT side IS offloadable: %s[%s]", c2.Name(), c2.Type())
			} else {
				log.Printf("RIGHT side is NOT offloadable")
			}

			// Handle OR operation
			if nx.Operator == "||" {
				// For traditional OR offloading (same field on both sides)
				if ok1 && ok2 && c1.Name() == c2.Name() {
					log.Printf("Processing OR with same field on both sides: %s", c1.Name())

					// For OR operations with same field, we can create a set constraint
					if c1.Type() == "equals" && c2.Type() == "equals" {
						eq1 := c1.(*EqualsConstraint)
						eq2 := c2.(*EqualsConstraint)
						setConstraint := NewSetConstraint(c1.Name(), []any{eq1.Value, eq2.Value})
						log.Printf("CREATED set constraint from OR of equals: %s with values %v",
							setConstraint.Name(), setConstraint.Values)
						return true, setConstraint
					}

					// Handle OR of range constraints specifically for pid field
					if c1.Type() == "range" && c2.Type() == "range" && c1.Name() == "pid" {
						r1 := c1.(*RangeConstraint)
						r2 := c2.(*RangeConstraint)

						// Check for complementary ranges (e.g., pid < 100 || pid > 1000)
						log.Printf("PROCESSING OR of range constraints for pid: r1[min:%v,max:%v] OR r2[min:%v,max:%v]",
							r1.Min, r1.Max, r2.Min, r2.Max)

						// Create a special "multi-range" constraint that can be handled by the PID offloader
						// We'll use a map to identify that this is a special type of range constraint with multiple parts
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

						log.Printf("CREATED multi-range constraint for pid with two ranges")
						return true, specialConstraint
					}

					// ORing ranges for other fields isn't generally offloadable unless they overlap significantly
					logOffloadFailure("OR", "cannot offload OR of non-equals constraints",
						fmt.Sprintf("%s and %s", c1.Type(), c2.Type()))
					return false, nil
				}

				// NEW: Handle partial OR offloading where only one side is offloadable
				if ok1 && !ok2 {
					log.Printf("OR operation with only left side offloadable: %s[%s]", c1.Name(), c1.Type())
					log.Printf("✅ Partial offloading of OR operation is possible")
					// Return the constraint from the offloadable side
					return true, c1
				}

				if !ok1 && ok2 {
					log.Printf("OR operation with only right side offloadable: %s[%s]", c2.Name(), c2.Type())
					log.Printf("✅ Partial offloading of OR operation is possible")
					// Return the constraint from the offloadable side
					return true, c2
				}

				// If we get here, neither side is offloadable
				logOffloadFailure("OR", "neither side is offloadable")
				return false, nil
			}

			// Handle AND operation
			if nx.Operator == "&&" {
				// If either side isn't offloadable, the whole thing isn't
				if !ok1 || !ok2 {
					logOffloadFailure("AND", "both sides must be offloadable")
					return false, nil
				}

				// If constraints apply to different fields, both can be offloaded
				if c1.Name() != c2.Name() {
					log.Printf("AND operation with different fields: %s and %s - both can be offloaded separately",
						c1.Name(), c2.Name())
					// This is a simplified approach - in reality, you'd need to track both constraints
					// and apply them at the offloading phase
					return true, c1 // Just return one of them for now
				}

				// For the same field, try to merge the constraints
				log.Printf("AND operation with same field: %s - attempting to merge constraints", c1.Name())
				mergedConstraint, canMerge := c1.Merge(c2)
				if canMerge {
					log.Printf("MERGED constraints successfully: %s[%s]",
						mergedConstraint.Name(), mergedConstraint.Type())
					return true, mergedConstraint
				}

				// Constraints are incompatible (e.g., x > 10 && x < 5)
				logOffloadFailure("AND", "constraints are incompatible and cannot be merged",
					fmt.Sprintf("%v AND %v", c1, c2))
				return false, nil
			}
		}

		logOffloadFailure("BinaryNode", "unsupported operator", nx.Operator)
		return false, nil

	case *ast.UnaryNode:
		log.Printf("CHECKING unary node: %s", nx.Operator)
		// Handle NOT operations if needed
		if nx.Operator == "!" {
			// NOT operations are typically harder to offload
			logOffloadFailure("UnaryNode", "NOT operations are not supported for offloading")
			return false, nil
		}
		return o.IsOffloadable(&nx.Node)

	default:
		logOffloadFailure("Node", "unsupported node type", fmt.Sprintf("%T", *node))
		return false, nil
	}
}

func (o *OffloadPatcher) RegisterOffloader(name string, oi *OffloadInfo) {
	o.offloaders[name] = append(o.offloaders[name], oi)
}

func (o *OffloadPatcher) Visit(node *ast.Node) {
	if _, ok := o.visited[node]; ok {
		return
	}

	log.Printf("> visiting offload node %T", *node)
	if ok, constraint := o.IsOffloadable(node); ok {
		log.Printf("offloading node %q %+v", constraint.Name(), constraint)

		// Special handling for OR nodes where only one side is offloadable
		if nx, isOr := (*node).(*ast.BinaryNode); isOr && nx.Operator == "||" {
			ok1, c1 := o.IsOffloadable(&nx.Left)
			ok2, c2 := o.IsOffloadable(&nx.Right)

			// If only one side is offloadable, we need to handle specially
			if (ok1 && !ok2) || (!ok1 && ok2) {
				log.Printf("Handling OR with partially offloadable expression")
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
				activated, err := o.ActivateOffload(partialConstraint.Name(), partialConstraint)
				if err != nil {
					log.Printf("Error activating partial offload: %v", err)
					return
				}

				if activated {
					// For OR with one side offloadable, we patch that side to 'true'
					// but leave the OR operation in place
					if sideToActivate == "left" {
						ast.Patch(&nx.Left, &ast.ConstantNode{Value: true})
						log.Printf("Successfully offloaded left side of OR: %s constraint", partialConstraint.Name())
					} else {
						ast.Patch(&nx.Right, &ast.ConstantNode{Value: true})
						log.Printf("Successfully offloaded right side of OR: %s constraint", partialConstraint.Name())
					}
					return
				}
			}
		}

		// Special handling for AND nodes with different field constraints
		if nx, isAnd := (*node).(*ast.BinaryNode); isAnd && nx.Operator == "&&" {
			// Check if this AND has two different field constraints
			ok1, c1 := o.IsOffloadable(&nx.Left)
			ok2, c2 := o.IsOffloadable(&nx.Right)

			if ok1 && ok2 && c1.Name() != c2.Name() {
				log.Printf("Handling AND with different fields: %s and %s", c1.Name(), c2.Name())

				// Activate both offloaders
				activated1, err1 := o.ActivateOffload(c1.Name(), c1)
				activated2, err2 := o.ActivateOffload(c2.Name(), c2)

				if err1 != nil || err2 != nil {
					log.Printf("Error activating offloaders: %v, %v", err1, err2)
					return
				}

				if activated1 && activated2 {
					// Replace the node with a constant true
					ast.Patch(node, &ast.ConstantNode{Value: true})
					log.Printf("Successfully offloaded both %s and %s constraints", c1.Name(), c2.Name())
					return
				}
			}
		}

		// For standard (non-OR, non-AND) offloadable nodes
		activated, err := o.ActivateOffload(constraint.Name(), constraint)
		if err != nil {
			log.Printf("Error activating offload: %v", err)
			return
		}

		if activated {
			// Replace the node with a constant true since this part will be handled in the kernel
			ast.Patch(node, &ast.ConstantNode{Value: true})
			log.Printf("Successfully offloaded %s constraint", constraint.Name())
		}
	}
}
