// Copyright 2022 The Inspektor Gadget authors
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

package types

const (
	ProfileUserParam   = "user"
	ProfileKernelParam = "kernel"
)

type Report struct {
	Node      string `json:"node,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Container string `json:"container,omitempty"`

	Comm        string   `json:"comm,omitempty"`
	Pid         uint32   `json:"pid,omitempty"`
	UserStack   []string `json:"user_stack,omitempty"`
	KernelStack []string `json:"kernel_stack,omitempty"`
	Count       uint64   `json:"count,omitempty"`
}
