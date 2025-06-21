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
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

// ConstraintHandler provides common utility functions for handling constraints
type ConstraintHandler struct {
	Logger *logrus.Entry
	Name   string
	MaxSetSize int
}

// NewConstraintHandler creates a new utility helper for constraint handling
func NewConstraintHandler(name string) *ConstraintHandler {
	return &ConstraintHandler{
		Logger: logrus.WithField("offloader", name),
		Name: name,
		MaxSetSize: 10, // Default max set size
	}
}

// WithMaxSetSize configures the maximum set size for set constraints
func (h *ConstraintHandler) WithMaxSetSize(size int) *ConstraintHandler {
	h.MaxSetSize = size
	return h
}

// CheckEqualsConstraint checks if an equals constraint can be offloaded
func (h *ConstraintHandler) CheckEqualsConstraint(constraint *EqualsConstraint) (bool, error) {
	h.Logger.Debugf("Checking equals constraint with value: %v", constraint.Value)
	return true, nil
}

// CheckSetConstraint checks if a set constraint can be offloaded
func (h *ConstraintHandler) CheckSetConstraint(constraint *SetConstraint) (bool, error) {
	// Check that the set size is manageable
	if len(constraint.Values) <= h.MaxSetSize {
		h.Logger.Debugf("Set constraint with %d values is supported", len(constraint.Values))
		return true, nil
	}

	h.Logger.Debugf("Set constraint too large for offload - limit %d, got %d values", 
		h.MaxSetSize, len(constraint.Values))
	return false, nil
}

// CheckRangeConstraint checks if a range constraint can be offloaded
func (h *ConstraintHandler) CheckRangeConstraint(constraint *RangeConstraint) (bool, error) {
	// Check for special multi-range type (OR of ranges)
	if constraint.Type() == "multi-range" {
		h.Logger.Debugf("Multi-range constraint is supported (OR of ranges)")
		return true, nil
	}

	// Standard range constraint
	h.Logger.Debugf("Range constraint is supported - min: %v, max: %v", 
		constraint.Min, constraint.Max)
	return true, nil
}

// GetStringValue safely extracts a string value from a constraint
func (h *ConstraintHandler) GetStringValue(value any) (string, bool) {
	strValue, ok := value.(string)
	if !ok {
		h.Logger.Debugf("Value is not a string: %T", value)
		return "", false
	}
	return strValue, true
}

// GetNumericValue safely extracts a numeric value from a constraint and converts it to int64
func (h *ConstraintHandler) GetNumericValue(value any) (int64, bool) {
	float, ok := toFloat64(value)
	if !ok {
		h.Logger.Debugf("Value is not numeric: %T", value)
		return 0, false
	}
	return int64(float), true
}

// ActivateEqualsConstraint activates an equals constraint
func (h *ConstraintHandler) ActivateEqualsConstraint(ctx context.Context, constraint *EqualsConstraint, 
	activator func(context.Context, any) (bool, error)) (bool, error) {
	return activator(ctx, constraint.Value)
}

// ActivateSetConstraint activates a set constraint
func (h *ConstraintHandler) ActivateSetConstraint(ctx context.Context, constraint *SetConstraint,
	activator func(context.Context, []any) (bool, error)) (bool, error) {
	return activator(ctx, constraint.Values)
}

// ActivateRangeConstraint activates a range constraint
func (h *ConstraintHandler) ActivateRangeConstraint(ctx context.Context, constraint *RangeConstraint,
	activator func(context.Context, any, any) (bool, error)) (bool, error) {
	return activator(ctx, constraint.Min, constraint.Max)
}

// CheckGenericConstraint provides a generic constraint checking function
func (h *ConstraintHandler) CheckGenericConstraint(c any) (bool, error) {
	switch constraint := c.(type) {
	case *EqualsConstraint:
		return h.CheckEqualsConstraint(constraint)
	case *SetConstraint:
		return h.CheckSetConstraint(constraint)
	case *RangeConstraint:
		return h.CheckRangeConstraint(constraint)
	default:
		h.Logger.Debugf("Constraint type %T not supported for offload", c)
		return false, nil
	}
}

// ActivateStringEqualsConstraint activates an equals constraint with a string value
func (h *ConstraintHandler) ActivateStringEqualsConstraint(ctx context.Context, c any, 
	activator func(context.Context, string) (bool, error)) (bool, error) {

	constraint, ok := c.(*EqualsConstraint)
	if !ok {
		return false, fmt.Errorf("expected EqualsConstraint, got %T", c)
	}

	strValue, ok := h.GetStringValue(constraint.Value)
	if !ok {
		return false, fmt.Errorf("expected string value, got %T", constraint.Value)
	}

	return activator(ctx, strValue)
}

// ActivateNumericEqualsConstraint activates an equals constraint with a numeric value
func (h *ConstraintHandler) ActivateNumericEqualsConstraint(ctx context.Context, c any, 
	activator func(context.Context, int64) (bool, error)) (bool, error) {

	constraint, ok := c.(*EqualsConstraint)
	if !ok {
		return false, fmt.Errorf("expected EqualsConstraint, got %T", c)
	}

	numValue, ok := h.GetNumericValue(constraint.Value)
	if !ok {
		return false, fmt.Errorf("expected numeric value, got %T", constraint.Value)
	}

	return activator(ctx, numValue)
}

// ActivateNumericRangeConstraint activates a range constraint with numeric min/max values
func (h *ConstraintHandler) ActivateNumericRangeConstraint(ctx context.Context, c any, 
	activator func(context.Context, *int64, *int64) (bool, error)) (bool, error) {

	constraint, ok := c.(*RangeConstraint)
	if !ok {
		return false, fmt.Errorf("expected RangeConstraint, got %T", c)
	}

	// Handle special multi-range type
	if constraint.Type() == "multi-range" {
		h.Logger.Debugf("Activating multi-range constraint")
		// Implementation for multi-range would be domain-specific
		// For example purposes, we'll treat it as a regular range constraint
		return activator(ctx, nil, nil)
	}

	// Convert min/max to int64 pointers
	var minPtr, maxPtr *int64

	if constraint.Min != nil {
		minVal, ok := h.GetNumericValue(constraint.Min)
		if ok {
			minPtr = &minVal
		}
	}

	if constraint.Max != nil {
		maxVal, ok := h.GetNumericValue(constraint.Max)
		if ok {
			maxPtr = &maxVal
		}
	}

	return activator(ctx, minPtr, maxPtr)
}

// ActivateStringSetConstraint activates a set constraint with string values
func (h *ConstraintHandler) ActivateStringSetConstraint(ctx context.Context, c any, 
	activator func(context.Context, []string) (bool, error)) (bool, error) {

	constraint, ok := c.(*SetConstraint)
	if !ok {
		return false, fmt.Errorf("expected SetConstraint, got %T", c)
	}

	// Convert values to strings
	strings := make([]string, 0, len(constraint.Values))
	for _, val := range constraint.Values {
		strVal, ok := h.GetStringValue(val)
		if !ok {
			return false, fmt.Errorf("expected string values in set, got %T", val)
		}
		strings = append(strings, strVal)
	}

	return activator(ctx, strings)
}

// ActivateNumericSetConstraint activates a set constraint with numeric values
func (h *ConstraintHandler) ActivateNumericSetConstraint(ctx context.Context, c any, 
	activator func(context.Context, []int64) (bool, error)) (bool, error) {

	constraint, ok := c.(*SetConstraint)
	if !ok {
		return false, fmt.Errorf("expected SetConstraint, got %T", c)
	}

	// Convert values to int64
	numbers := make([]int64, 0, len(constraint.Values))
	for _, val := range constraint.Values {
		numVal, ok := h.GetNumericValue(val)
		if !ok {
			return false, fmt.Errorf("expected numeric values in set, got %T", val)
		}
		numbers = append(numbers, numVal)
	}

	return activator(ctx, numbers)
}
