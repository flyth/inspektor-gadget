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
	"context"
	"sync"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type gadgetState int

const (
	stateRunning gadgetState = iota
	statePaused
	stateError
)

type gadgetInstance struct {
	mu              sync.Mutex
	request         *api.OCIGadgetRunRequest
	eventBuffer     [][]byte
	eventBufferOffs int
	eventOverflow   bool
	gadgetCtx       *gadgetcontext.GadgetContext
	clients         map[*gadgetInstanceClient]struct{}
	cancel          func()
	state           gadgetState
	error           error
}

func (i *gadgetInstance) RunGadget(
	ctx context.Context,
	runtime runtime.Runtime,
	logger logger.Logger,
	request *api.OCIGadgetRunRequest,
) error {
	return nil
}
