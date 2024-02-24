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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type Store interface {
	api.OCIGadgetInstanceManagerStoreServer
	InstallOCIGadgetInstance(ctx context.Context, req *api.InstallOCIGadgetInstanceRequest) (*api.InstallOCIGadgetInstanceResponse, error)
	RemoveOCIGadgetInstance(context.Context, *api.OCIGadgetInstanceId) (*api.StatusResponse, error)
	ListOCIGadgetInstances(context.Context, *api.ListOCIGadgetInstancesRequest) (*api.ListOCIGadgetInstanceResponse, error)
}
