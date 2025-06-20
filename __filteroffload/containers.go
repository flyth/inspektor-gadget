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
	log "github.com/sirupsen/logrus"
)

func ContainerOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "container",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("CONTAINER checking constraint %+v", c)
			if _, ok := c.(*EqualsConstraint); ok {
				log.Printf("> equals is ok")
				return true, nil
			}
			return false, nil
		},
		OffloadCallback: func(c any) (bool, error) {
			return false, nil
		},
	}
}

func ParamOffloader() *OffloadInfo {
	return &OffloadInfo{
		Name: "pid",
		CheckCallback: func(c any) (bool, error) {
			log.Printf("PID checking constraint %+v", c)
			if _, ok := c.(*EqualsConstraint); ok {
				log.Printf("> equals is ok")
				return true, nil
			}
			return false, nil
		},
		OffloadCallback: func(c any) (bool, error) {
			return false, nil
		},
	}
}
