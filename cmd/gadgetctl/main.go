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

package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	rootCmd := &cobra.Command{
		Use:   filepath.Base(os.Args[0]),
		Short: "Collection of gadgets for containers",
	}
	common.AddVerboseFlag(rootCmd)
	rootCmd.AddCommand(common.NewVersionCmd())

	runtime := grpcruntime.New()

	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	err := runtime.Init(runtimeGlobalParams)
	if err != nil {
		log.Fatalf("initializing runtime: %v", err)
	}
	runtime.InitDeployInfo()
	hiddenColumnTags := []string{"kubernetes"}
	common.AddCommandsFromRegistry(rootCmd, runtime, hiddenColumnTags)

	rootCmd.AddCommand(common.NewSyncCommand(runtime))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Local
}
