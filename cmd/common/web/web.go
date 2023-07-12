// Copyright 2023 The Inspektor Gadget authors
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

package web

import (
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence/files"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/ws"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func StartWS(runtime runtime.Runtime, persistenceManager *persistence.Manager) error {
	websocketServer := ws.NewWebServer(runtime, persistenceManager)
	return websocketServer.Run("unix", "")
}

func AddWebCommand(rootCmd *cobra.Command, runtime runtime.Runtime) {
	cmd := &cobra.Command{
		Use:   "web",
		Short: "start webserver",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := persistence.NewManager(runtime, false)
			store, _ := files.New(mgr)
			mgr.SetStore(store)

			return StartWS(runtime, mgr)
		},
	}
	rootCmd.AddCommand(cmd)
}
