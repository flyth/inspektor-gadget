// Copyright 2024 The Inspektor Gadget authors
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

package instancemanager

import (
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Manager struct {
	api.OCIGadgetInstanceManagerServer

	mu              sync.Mutex
	gadgetInstances map[string]*gadgetInstance
	waitingRoom     sync.Map

	asyncGadgetRunCreation bool
	runtime                runtime.Runtime
	Store
}

func New(runtime runtime.Runtime, async bool) *Manager {
	return &Manager{
		gadgetInstances:        make(map[string]*gadgetInstance),
		asyncGadgetRunCreation: async,
		runtime:                runtime,
	}
}

func (m *Manager) SetStore(store Store) {
	m.Store = store
}

func (m *Manager) RunOCIGadget(id string, req *api.OCIGadgetRunRequest) error {
	return nil
}

func (m *Manager) StopOCIGadget(id string) error {
	// TODO: make this generic control
	return nil
}

func (m *Manager) RemoveOCIGadget(id string) error {
	return nil
}
