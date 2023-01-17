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

package gadgets_test

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	log "github.com/sirupsen/logrus"
)

type DemoGadget struct{}

func (g *DemoGadget) Name() string {
	return "bind"
}

func (g *DemoGadget) Description() string {
	return "bindsnoop traces the kernel functions performing socket binding."
}

func (g *DemoGadget) GetParams() params.Params {
	return params.Params{
		{
			Key:          "pid",
			Alias:        "",
			DefaultValue: "",
			Description:  "",
			IsMandatory:  false,
			Tags:         nil,
		},
		/*
			{
				Key:          "ports",
				Alias:        "P",
				DefaultValue: "",
				Description:  "",
				IsMandatory:  false,
				Tags:         nil,
			},
			{
				Key:          "ignore_errors",
				Alias:        "i",
				DefaultValue: "",
				Description:  "",
				IsMandatory:  false,
				Tags:         nil,
			},

		*/
	}
}

func TestGadget(t *testing.T) {
	g := &DemoGadget{}
	params := g.GetParams()
	for _, p := range params {
		err := p.SetString("3")
		if err != nil {
			log.Printf("error: %v", err)
		}
		log.Printf("%s => %+v", p.Key, p.Value)
	}
}
