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

package legacy

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	log "github.com/sirupsen/logrus"
)

type Frontend struct{}

func NewFrontend() frontends.Frontend {
	return &Frontend{}
}

func (f *Frontend) Output(payload string) {
	fmt.Fprintln(os.Stdout, payload)
}

func (f *Frontend) Error(severity int, message string) {
	fmt.Fprintln(os.Stderr, message)
}

func (f *Frontend) GetContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Debugf("got signal, cancelling context")
		cancel()
		<-stop
		log.Debugf("got signal again, exiting")
		// On second signal, exit forcefullys
		os.Exit(1)
	}()
	return ctx
}

func (f *Frontend) Close() {
}
