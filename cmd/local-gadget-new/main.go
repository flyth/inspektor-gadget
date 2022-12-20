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

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/modern"
	_ "github.com/inspektor-gadget/inspektor-gadget/internal/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "local-gadget",
		Short: "Collection of gadgets for containers",
	}

	var verbose bool
	rootCmd.AddCommand()
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
		modern.NewInspektor()
	}
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enables more/debug output")

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
