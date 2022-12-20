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

import "github.com/gdamore/tcell/v2/views"

type LogPanel struct {
	views.Panel
	textarea *views.TextArea
}

func NewLogPanel(app *Frontend) *LogPanel {
	p := &LogPanel{}
	p.textarea = views.NewTextArea()

	p.AddWidget(p.textarea, 1.0)

	title := views.NewText()
	title.SetText("Foobar")
	p.SetTitle(title)
	return p
}

func (p *LogPanel) SetText(text string) {
	p.textarea.SetContent(text)
}
