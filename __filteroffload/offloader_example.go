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

	log "github.com/sirupsen/logrus"
)

// This file contains examples of how to implement custom offloaders
// using the constraint utilities.

// Example 1: String-based offloader (e.g., for namespace filtering)
func NamespaceOffloader() *OffloadInfo {
	handler := NewConstraintHandler("namespace").WithMaxSetSize(5)

	return &OffloadInfo{
		Name: "namespace",
		CheckCallback: func(c any) (bool, error) {
			// For simple cases, you can use the generic constraint checker
			return handler.CheckGenericConstraint(c)
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Use the string-specific helper
				return handler.ActivateStringEqualsConstraint(ctx, constraint,
					func(ctx context.Context, value string) (bool, error) {
						// Here you would implement the actual eBPF program configuration
						log.Debugf("Activating namespace filter for: %s", value)

						// Implementation example (pseudo-code):
						//   ebpfProgram.SetNamespaceFilter(value)

						return true, nil
					})

			case *SetConstraint:
				// Use the set-specific helper
				return handler.ActivateStringSetConstraint(ctx, constraint,
					func(ctx context.Context, values []string) (bool, error) {
						log.Debugf("Activating namespace filter for multiple values: %v", values)

						// Implementation example (pseudo-code):
						//   for _, ns := range values {
						//     ebpfProgram.AddNamespaceToFilter(ns)
						//   }

						return true, nil
					})

			default:
				return false, fmt.Errorf("unsupported constraint type for namespace offload: %T", c)
			}
		},
	}
}

// Example 2: Port number offloader with range support
func PortOffloader() *OffloadInfo {
	handler := NewConstraintHandler("port").WithMaxSetSize(10)

	return &OffloadInfo{
		Name: "port",
		CheckCallback: func(c any) (bool, error) {
			// For custom validation logic, you can implement your own check
			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Check if port is within valid range (1-65535)
				portValue, ok := handler.GetNumericValue(constraint.Value)
				if !ok {
					return false, nil
				}

				if portValue < 1 || portValue > 65535 {
					log.Debugf("Port value %d is outside valid range (1-65535)", portValue)
					return false, nil
				}

				return true, nil

			case *RangeConstraint:
				// Validate the range bounds if present
				if constraint.Min != nil {
					minVal, ok := handler.GetNumericValue(constraint.Min)
					if !ok || minVal < 1 {
						log.Debugf("Invalid min port value: %v", constraint.Min)
						return false, nil
					}
				}

				if constraint.Max != nil {
					maxVal, ok := handler.GetNumericValue(constraint.Max)
					if !ok || maxVal > 65535 {
						log.Debugf("Invalid max port value: %v", constraint.Max)
						return false, nil
					}
				}

				return true, nil

			case *SetConstraint:
				// Delegate to the built-in set checker
				return handler.CheckSetConstraint(constraint)

			default:
				return false, nil
			}
		},
		OffloadCallback: func(ctx context.Context, c any) (bool, error) {
			switch constraint := c.(type) {
			case *EqualsConstraint:
				return handler.ActivateNumericEqualsConstraint(ctx, constraint,
					func(ctx context.Context, value int64) (bool, error) {
						log.Debugf("Activating port filter for: %d", value)

						// Implementation example (pseudo-code):
						//   ebpfProgram.SetPortFilter(uint16(value))

						return true, nil
					})

			case *RangeConstraint:
				return handler.ActivateNumericRangeConstraint(ctx, constraint,
					func(ctx context.Context, min, max *int64) (bool, error) {
						// Ensure port values are within valid range
						var minPort int64 = 1
						var maxPort int64 = 65535

						if min != nil {
							minPort = *min
						}

						if max != nil {
							maxPort = *max
						}

						log.Debugf("Activating port range filter: %d-%d", minPort, maxPort)

						// Implementation example (pseudo-code):
						//   ebpfProgram.SetPortRangeFilter(uint16(minPort), uint16(maxPort))

						return true, nil
					})

			case *SetConstraint:
				return handler.ActivateNumericSetConstraint(ctx, constraint,
					func(ctx context.Context, values []int64) (bool, error) {
						log.Debugf("Activating port filter for multiple values: %v", values)

						// Implementation example (pseudo-code):
						//   for _, port := range values {
						//     ebpfProgram.AddPortToFilter(uint16(port))
						//   }

						return true, nil
					})

			default:
				return false, fmt.Errorf("unsupported constraint type for port offload: %T", c)
			}
		},
	}
}
