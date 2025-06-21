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

	log "github.com/sirupsen/logrus"
)

func ContainerOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "container",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("CONTAINER checking constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				log.Printf("✅ CONTAINER: equals constraint is supported - value: %v", constraint.Value)
				return true, nil

			case *SetConstraint:
				// Container ID offload can support a set of container IDs
				// Check that the set size is manageable
				if len(constraint.Values) <= 10 { // Arbitrary limit for demonstration
					log.Printf("✅ CONTAINER: set constraint with %d values is supported - values: %v",
						len(constraint.Values), constraint.Values)
					return true, nil
				}
				log.Printf("❌ CONTAINER: set constraint too large for offload - limit 10, got %d values",
					len(constraint.Values))
				return false, nil

			default:
				log.Printf("❌ CONTAINER: constraint type %T not supported for offload", c)
				return false, nil
			}
		},
		OffloadCallback: func(c any) (bool, error) {
			log.Printf("CONTAINER activating offload for constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				containerID, ok := constraint.Value.(string)
				if !ok {
					return false, fmt.Errorf("container ID must be a string, got %T", constraint.Value)
				}

				// In a real implementation, this would configure the eBPF program
				log.Printf("> activating container filter for ID: %s", containerID)
				return true, nil

			case *SetConstraint:
				// In a real implementation, this would configure the eBPF program with multiple values
				log.Printf("> activating container filter for multiple IDs: %v", constraint.Values)
				return true, nil

			default:
				return false, fmt.Errorf("unsupported constraint type for container offload: %T", c)
			}
		},
	}
}

func ParamOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "pid",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("PID checking constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				log.Printf("✅ PID: equals constraint is supported - value: %v", constraint.Value)
				return true, nil

			case *RangeConstraint:
				// Check for special multi-range type (OR of ranges)
				if constraint.Type() == "multi-range" {
					log.Printf("✅ PID: multi-range constraint is supported (OR of ranges)")
					return true, nil
				}

				// PID offload supports regular range filters
				log.Printf("✅ PID: range constraint is supported - min: %v, max: %v",
					constraint.Min, constraint.Max)
				return true, nil

			case *SetConstraint:
				// PID offload can support a limited set of PIDs
				if len(constraint.Values) <= 16 { // Arbitrary limit for demonstration
					log.Printf("✅ PID: set constraint with %d values is supported - values: %v",
						len(constraint.Values), constraint.Values)
					return true, nil
				}
				log.Printf("❌ PID: set constraint too large for offload - limit 16, got %d values",
					len(constraint.Values))
				return false, nil

			default:
				log.Printf("❌ PID: constraint type %T not supported for offload", c)
				return false, nil
			}
		},
		OffloadCallback: func(c any) (bool, error) {
			log.Printf("PID activating offload for constraint %+v", c)

			switch constraint := c.(type) {
			case *EqualsConstraint:
				// Handle different integer types
				var pidValue int64
				var ok bool

				switch v := constraint.Value.(type) {
				case int64:
					pidValue = v
					ok = true
				case int:
					pidValue = int64(v)
					ok = true
				case float64:
					pidValue = int64(v)
					ok = true
				default:
					ok = false
				}

				if !ok {
					return false, fmt.Errorf("PID must be a numeric value, got %T", constraint.Value)
				}

				// In a real implementation, this would configure the eBPF program
				log.Printf("> activating PID filter for: %d", pidValue)
				return true, nil

			case *RangeConstraint:
				// Handle special multi-range type for OR of ranges
				if constraint.Type() == "multi-range" {
					log.Printf("> activating PID multi-range filter with two separate ranges")
					return true, nil
				}

				// Convert min/max values to integers for consistency
				var minVal, maxVal interface{} = nil, nil

				// Handle min value if present
				if constraint.Min != nil {
					switch min := constraint.Min.(type) {
					case int64:
						minVal = min
					case int:
						minVal = int64(min)
					case float64:
						minVal = int64(min)
					default:
						log.Printf("WARNING: Unsupported min type: %T", constraint.Min)
					}
				}

				// Handle max value if present
				if constraint.Max != nil {
					switch max := constraint.Max.(type) {
					case int64:
						maxVal = max
					case int:
						maxVal = int64(max)
					case float64:
						maxVal = int64(max)
					default:
						log.Printf("WARNING: Unsupported max type: %T", constraint.Max)
					}
				}

				// In a real implementation, this would configure the eBPF program with a range
				log.Printf("> activating PID range filter: min=%v, max=%v", minVal, maxVal)
				return true, nil

			case *SetConstraint:
				// In a real implementation, this would configure the eBPF program with multiple values
				log.Printf("> activating PID filter for multiple values: %v", constraint.Values)
				return true, nil

			default:
				return false, fmt.Errorf("unsupported constraint type for PID offload: %T", c)
			}
		},
	}
}
