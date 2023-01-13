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

package main

import (
	"os"

	"github.com/blang/semver"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	_ "github.com/inspektor-gadget/inspektor-gadget/internal/runtime/remote"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

func init() {
	utils.KubectlGadgetVersion, _ = semver.New("")
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "kubectl-gadget",
		Short: "Collection of gadgets for Kubernetes developers",
	}

	rootCmd.AddCommand()

	// Prepare categories
	categories := gadgets.GetCategories()
	for category, description := range categories {
		rootCmd.AddCommand(&cobra.Command{
			Use:   category,
			Short: description,
		})
	}

	common.AddCommandsFromRegistry(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
