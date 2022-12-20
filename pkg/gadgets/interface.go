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

package gadgets

import (
	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	CategoryAdvise   = "advise"
	CategoryAudit    = "audit"
	CategoryProfile  = "profile"
	CategorySnapshot = "snapshot"
	CategoryTop      = "top"
	CategoryTrace    = "trace"
)

var categories = map[string]string{
	CategoryAdvise:   "Recommend system configurations based on collected information",
	CategoryAudit:    "Audit a subsystem",
	CategoryProfile:  "Profile different subsystems",
	CategorySnapshot: "Take a snapshot of a subsystem and print it",
	CategoryTop:      "Gather, sort and periodically report events according to a given criteria",
	CategoryTrace:    "Trace and print system events",
}

func GetCategories() map[string]string {
	return categories
}

// GadgetType defines how a gadget is actually run
type GadgetType string

const (
	TypeTrace             GadgetType = "trace"             // Normal trace gadgets
	TypeTracePerContainer GadgetType = "tracePerContainer" // Using Attach() like dns, sni and so on
	TypeTraceIntervals    GadgetType = "traceIntervals"    // top gadgets expecting arrays of events
	TypeOneShot           GadgetType = "oneShot"           // Gadgets that only run once
	TypeProfile           GadgetType = "profile"           // Gadgets that run until the user stops or it times out and then shows results
)

func (t GadgetType) CanSort() bool {
	return t == TypeOneShot || t == TypeTraceIntervals
}

// Gadget is the main interface for handling gadgets
type Gadget interface {
	// Name provides the name of the gadget. This is used for the calling the gadget, auto-creating the cobra commands,
	// logging, etc.
	Name() string

	// Description provides a short description of the gadget. This is used for a quick help in cobra, help, web-interface
	// etc.
	Description() string

	// Category is used for cobra sub-commands and categories on the web interface.
	Category() string

	// Type is used to differentiate between how gadgets are run. The type essentially controls the workflow of the
	// gadget.
	Type() GadgetType

	// Params returns a map of configuration parameters. These hold also default values, descriptions, validators and
	// so on. Used whenever a gadget is called somehow. Auto-creates parameters for cobra as well.
	Params() params.Params

	// Columns returns a columnhelpers.Columns instance that can handle events and do certain operations on them
	// (sorting, filtering, etc.) without the caller needing to know about the underlying types.
	Columns() columnhelpers.Columns

	// EventPrototype returns a blank event. Useful for checking for interfaces on it (see enrichers).
	EventPrototype() any
}
