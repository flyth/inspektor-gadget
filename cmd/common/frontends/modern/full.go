// Copyright 2022-2023 The Inspektor Gadget authors
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
	"sort"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Inspektor struct {
	app           *tview.Application
	log           *tview.TextView
	main          *tview.Pages
	logger        *log.Logger
	runtime       runtime.Runtime
	columnFilters []columns.ColumnFilter
}

func NewInspektor(runtime runtime.Runtime, columnFilters []columns.ColumnFilter) *Inspektor {
	app := &Inspektor{
		logger:        log.StandardLogger(),
		runtime:       runtime,
		columnFilters: columnFilters,
	}
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkBlue

	app.init()
	return app
}

func (a *Inspektor) init() {
	a.app = tview.NewApplication()

	a.log = tview.NewTextView().SetWrap(false)
	a.log.SetBorder(true)
	a.log.SetDynamicColors(true)

	// Redirect log output to dedicated panel
	log.SetOutput(a.log)
	a.logger.SetOutput(a.log)
	a.logger.SetLevel(log.DebugLevel)
	log.Print("Welcome to Inspektor Gadget")

	a.main = tview.NewPages()
	a.main.AddAndSwitchToPage("main", a.gadgetCategorySelect(), true)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(a.main, 0, 1, true).AddItem(a.log, 12, 0, false)
	frame := tview.NewFrame(flex).AddText("Inspektor Gadget", true, tview.AlignCenter, tcell.ColorWhite).SetBorders(0, 0, 0, 0, 0, 0)

	a.app.SetRoot(frame, true)

	a.app.Run()
}

func centered(primitive tview.Primitive, title string, width, height int) tview.Primitive {
	content := tview.NewFlex().AddItem(primitive, 0, 1, true)
	content.SetBorder(true).SetBorderPadding(1, 1, 2, 2)
	if title != "" {
		content.SetTitle("[ " + title + " ]")
	}
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(content, height, 3, true).
			AddItem(nil, 0, 1, false), width, 4, true).
		AddItem(nil, 0, 1, false)
}

func (a *Inspektor) gadgetError(category, gadgetName, error string) tview.Primitive {
	modal := tview.NewModal()
	modal.SetBorder(true)
	modal.SetTitle("[ Error ]")
	modal.SetText(error)
	modal.AddButtons([]string{"OK"})
	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		a.main.AddAndSwitchToPage("main", a.gadgetSelect(category), true)
	})
	return modal
}

func (a *Inspektor) runProfileGadget(category, gadgetName string, operatorParamCollection, operatorsParamCollection params.Collection, gadgetParams *params.Params) tview.Primitive {
	runtimeGlobalParams := a.runtime.GlobalParamDescs().ToParams()
	runtimeParams := a.runtime.ParamDescs().ToParams()

	// init/deinit runtime
	err := a.runtime.Init(runtimeGlobalParams) // TODO
	if err != nil {
		return a.gadgetError(category, gadgetName, err.Error())
	}
	// defer runtime.Close() // TODO

	gadget := gadgetregistry.Get(category, gadgetName)
	columns := gadget.Parser()
	if columns != nil {
		columns.SetColumnFilters(a.columnFilters...)
	}

	ctx, cancel := context.WithCancel(context.Background())

	operators.GetOperatorsForGadget(gadget).Init(operators.GlobalParamsCollection())

	// Create new runner
	gadgetCtx := gadgetcontext.New(
		ctx,
		"",
		a.runtime,
		runtimeParams,
		gadget,
		gadgetParams,
		operatorsParamCollection,
		columns,
		a.logger,
	)

	var outRes []byte
	var outErr error

	go func() {
		log.Infof("starting gadget")
		outRes, outErr = a.runtime.RunGadget(gadgetCtx)
		if err != nil {
			log.Errorf("running container: %v", err)
		}
	}()

	// Start gadget showing a profile indicator and waiting for a stop click
	modal := tview.NewModal()
	modal.SetTitle(gadgetName)
	modal.SetText("Profiling... Press 'Stop' to show results")
	modal.AddButtons([]string{"Stop"})

	doneFunc := func() {
		cancel()
		log.Printf("cancel called")
		time.Sleep(time.Second) // Wait for results

		outView := tview.NewTextView()
		outView.SetTitle("[ " + gadgetName + " ]")
		outView.SetBorder(true)

		if outErr != nil {
			outView.Write([]byte(outErr.Error()))
		} else {
			outView.Write(outRes)
		}

		outView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Key() {
			case tcell.KeyEscape:
				a.main.AddAndSwitchToPage("main", a.gadgetSelect(category), true)
				return nil
			}
			return event
		})

		a.main.AddAndSwitchToPage("main", outView, true)
	}

	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlC, tcell.KeyEscape:
			doneFunc()
			return nil
		}
		return event
	})

	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		doneFunc()
	})

	return modal
}

func (a *Inspektor) runGadget(category, gadgetName string, operatorParamCollection, operatorsParamCollection params.Collection, gadgetParams *params.Params) tview.Primitive {
	runtimeGlobalParams := a.runtime.GlobalParamDescs().ToParams()
	runtimeParams := a.runtime.ParamDescs().ToParams()

	// init/deinit runtime
	err := a.runtime.Init(runtimeGlobalParams) // TODO
	if err != nil {
		return a.gadgetError(category, gadgetName, err.Error())
	}
	// defer runtime.Close() // TODO

	gadget := gadgetregistry.Get(category, gadgetName)
	columns := gadget.Parser()
	columns.SetColumnFilters(a.columnFilters...)
	formatter := columns.GetTextColumnsFormatter()

	ctx, cancel := context.WithCancel(context.Background())

	operators.GetOperatorsForGadget(gadget).Init(operators.GlobalParamsCollection())

	// Create new gadgetCtx
	gadgetCtx := gadgetcontext.New(
		ctx,
		"",
		a.runtime,
		runtimeParams,
		gadget,
		gadgetParams,
		operatorsParamCollection,
		columns,
		a.logger,
	)

	gadgetCtx.Parser().SetLogCallback(func(severity logger.Level, fmt string, params ...any) {
		log.Infof(fmt, params...) // TODO
	})

	text := tview.NewTextView().SetWrap(false).SetScrollable(true)
	text.SetBorder(true)
	text.SetTitle("[ " + gadgetName + " ]")

	formatter.SetEventCallback(func(s string) {
		if gadget.Type() == gadgets.TypeTraceIntervals {
			text.Clear()
		}
		text.Write(append([]byte(s), '\n'))
		a.app.Draw()
	})
	gadgetCtx.Parser().SetEventCallback(formatter.EventHandlerFunc())
	gadgetCtx.Parser().SetEventCallback(formatter.EventHandlerFuncArray())

	go func() {
		_, err := a.runtime.RunGadget(gadgetCtx)
		if err != nil {
			log.Errorf("running container: %v", err)
		}
	}()

	text.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlC, tcell.KeyEscape:
			cancel()
			a.main.AddAndSwitchToPage("main", a.gadgetSelect(category), true)
			return nil
		}
		return event
	})

	return text
}

func (a *Inspektor) addParamsToForm(form *tview.Form, par *params.Params) {
	for _, p := range *par {
		func(p *params.Param) {
			title := p.GetTitle()
			log.Infof("added param %s", title)

			if len(p.PossibleValues) > 0 {
				initialValue := 0
				for idx, v := range p.PossibleValues {
					if v == p.String() {
						initialValue = idx
						break
					}
				}
				form.AddDropDown(title, p.PossibleValues, initialValue, func(option string, optionIndex int) {
					p.Set(option)
				})
				return
			}

			switch p.TypeHint {
			case params.TypeBool:
				form.AddCheckbox(title, p.String() == "true", func(checked bool) {
					if checked {
						p.Set("true")
						return
					}
					p.Set("false")
				})
			default:
				form.AddInputField(title, p.String(), 0, func(textToCheck string, lastChar rune) bool {
					return p.Validate(textToCheck) == nil
				}, func(text string) {
					p.Set(text)
				})
			}
		}(p)
		if p.Description != "" {
			form.AddTextView("", p.Description, 0, 1, false, false)
		}
	}
}

func (a *Inspektor) gadgetPrerun(category, gadgetName string) tview.Primitive {
	gadget := gadgetregistry.Get(category, gadgetName)
	if gadget == nil {
		return a.gadgetSelect(category)
	}

	gadgetParamDescs := gadget.ParamDescs()
	parser := gadget.Parser()
	if parser != nil {
		parser.SetColumnFilters(a.columnFilters...)
	}

	// Add params specific for the gadget type
	gadgetParamDescs.Add(gadgets.GadgetParams(gadget, parser)...)

	gadgetParams := gadgetParamDescs.ToParams()

	operatorParamCollection := operators.GlobalParamsCollection()
	gadgetOperators := operators.GetOperatorsForGadget(gadget)
	operatorPerGadgetParamCollection := gadgetOperators.ParamCollection()

	form := tview.NewForm()
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			a.main.AddAndSwitchToPage("main", a.gadgetSelect(category), true)
			return nil
		}
		return event
	})
	a.addParamsToForm(form, gadgetParams)
	for _, p := range operatorParamCollection {
		a.addParamsToForm(form, p)
	}
	for _, p := range operatorPerGadgetParamCollection {
		a.addParamsToForm(form, p)
	}
	form.AddButton("Run", func() {
		switch gadget.Type() {
		default:
			a.main.AddAndSwitchToPage("main", a.runGadget(category, gadgetName, operatorParamCollection, operatorPerGadgetParamCollection, gadgetParams), true)
		case gadgets.TypeProfile:
			a.main.AddAndSwitchToPage("main", a.runProfileGadget(category, gadgetName, operatorParamCollection, operatorPerGadgetParamCollection, gadgetParams), true)
		}
	})

	return centered(form, gadget.Name(), 0, 0)
}

func (a *Inspektor) gadgetSelect(category string) tview.Primitive {
	a.app.EnableMouse(true)

	list := tview.NewList()
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			a.main.AddAndSwitchToPage("main", a.gadgetCategorySelect(), true)
			return nil
		}
		return event
	})

	gadgetList := make([]gadgets.GadgetDesc, 0)
	for _, gadget := range gadgetregistry.GetAll() {
		gadgetList = append(gadgetList, gadget)
	}

	sort.Slice(gadgetList, func(i, j int) bool {
		return gadgetList[i].Name() < gadgetList[j].Name()
	})

	c := '1'
	for _, gadget := range gadgetList {
		if gadget.Category() != category {
			continue
		}
		func(gadget gadgets.GadgetDesc) {
			list.AddItem(gadget.Name(), gadget.Description(), c, func() {
				log.Infof("selected gadget %s", gadget.Name())
				a.main.AddAndSwitchToPage("main", a.gadgetPrerun(gadget.Category(), gadget.Name()), true)
			})
		}(gadget)
		c++
	}

	return centered(list, "Category: "+category, 0, 0)
}

func (a *Inspektor) gadgetCategorySelect() tview.Primitive {
	a.app.EnableMouse(true)

	list := tview.NewList()

	categories := gadgets.GetCategories()

	categoryNames := make([]string, 0)
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}

	sort.Strings(categoryNames)

	c := '1'
	for _, category := range categoryNames {
		func(category string) {
			list.AddItem(cases.Title(language.English).String(category), categories[category], c, func() {
				log.Infof("selected category %s", category)
				a.main.AddAndSwitchToPage("main", a.gadgetSelect(category), true)
			})
		}(category)
		c++
	}
	return centered(list, "Gadget Categories", 0, 0)
}
