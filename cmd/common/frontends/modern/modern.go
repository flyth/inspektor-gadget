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

package modern

import (
	"context"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	"github.com/rivo/tview"
	log "github.com/sirupsen/logrus"
)

type Frontend struct {
	ctx    context.Context
	cancel context.CancelFunc
	app    *tview.Application
	text   *tview.TextView
	log    *tview.TextView
}

func NewFrontend() frontends.Frontend {
	f := &Frontend{}
	f.init()
	return f
}

func (f *Frontend) init() {
	f.app = tview.NewApplication()

	f.text = tview.NewTextView().SetWrap(false).SetScrollable(true) // .SetChangedFunc(func() { f.app.Draw() })
	f.text.SetBorder(true)

	f.log = tview.NewTextView().SetWrap(false)
	f.log.SetBorder(true)

	log.SetOutput(f.log)

	go func() {
		for range time.NewTicker(time.Second).C {
			log.Printf("line")
			f.app.Draw()
		}
	}()

	flex := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(f.text, 0, 1, true).AddItem(f.log, 8, 0, false)
	frame := tview.NewFrame(flex).AddText("Inspektor Gadget", true, tview.AlignCenter, tcell.ColorWhite).SetBorders(0, 0, 0, 0, 0, 0)

	f.app.SetRoot(frame, true)

	go func() {
		f.app.Run()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	f.ctx = ctx
	f.cancel = cancel

	return
}

func (f *Frontend) quit() {
	f.app.Stop()
}

func (f *Frontend) Close() {
	f.quit()
}

func (f *Frontend) Output(payload string) {
	f.app.QueueUpdateDraw(func() {
		// f.text.SetText(payload)
		f.text.Write(append([]byte(payload), '\n'))
	})
}

func (f *Frontend) Error(severity int, message string) {
	// fmt.Fprintln(os.Stderr, message)
}

func (f *Frontend) GetContext() context.Context {
	return f.ctx
}
