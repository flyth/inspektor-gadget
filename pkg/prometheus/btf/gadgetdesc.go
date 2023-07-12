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

package prombtf

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

func (c *Collector) Name() string {
	return "PromBTF"
}

func (c *Collector) Description() string {
	return "Prometheus Metric Collector from BTF"
}

func (c *Collector) Category() string {
	return ""
}

func (c *Collector) Type() gadgets.GadgetType {
	return gadgets.TypeOther
}

func (c *Collector) ParamDescs() params.ParamDescs {
	return nil
}

func (c *Collector) Parser() parser.Parser {
	return nil
}

func (c *Collector) EventPrototype() any {
	return &CollectorData{collector: c}
}
