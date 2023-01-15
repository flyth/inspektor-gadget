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

package params

import (
	"fmt"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type (
	Params           []*Param
	ParamMap         map[string]string
	ParamsCollection map[string]Params
)

type Param struct {
	// Key is the name under which this param is registered; this will also be the key when
	// getting a key/value map
	Key string `json:"key"`

	// Alias is a shortcut for this parameter, usually a single character used for command line
	// interfaces
	Alias string `json:"alias"`

	// Title is an optional (pretty) alternative to key and used in user interfaces
	Title string `json:"title"`

	// DefaultValue is the value that will be used if no other value has been assigned
	DefaultValue string `json:"defaultValue"`

	// Description holds an optional explanation for this parameter; shown in user interfaces
	Description string `json:"description"`

	// IsMandatory will be considered when validating; if the param has no value assigned and
	// also no DefaultValue is set, validation will fail
	IsMandatory bool `json:"isMandatory"`

	// Tags can be used to skip parameters not needed for a specific environment
	Tags []string `json:"tags"`

	// Validator is an optional function that will be called upon validation; may or may
	// not be called in user interfaces. Setting TypeHint is preferred, but can also be used
	// in combination with the Validator.
	Validator ParamValidator `json:"-"`

	// TypeHint is the preferred way to set the type of this parameter as it will invoke a
	// matching validator automatically; if unset, a value of "string" is assumed
	TypeHint TypeHint `json:"type"`

	// PossibleValues holds all possible values for this parameter and will be considered
	// when validating
	PossibleValues []string `json:"possibleValues"`

	value    string
	assigned bool
	Value
}

// GetTitle returns a human friendly title of the field; is no Title has been specified,
// the Key will be used with the first letter upper-cased
func (p *Param) GetTitle() string {
	if p.Title != "" {
		return p.Title
	}
	return cases.Title(language.English).String(p.Key)
}

// PreValidate validates a string against the given parameter
func (p *Param) PreValidate(value string) error {
	if value != "" {
		if len(p.PossibleValues) > 0 {
			for _, v := range p.PossibleValues {
				if v == value {
					return nil
				}
			}
		}
		if validator, ok := typeHintValidators[p.TypeHint]; ok {
			err := validator(value)
			if err != nil {
				return fmt.Errorf("invalid value %q as %q: %w", value, p.Key, err)
			}
		}
		if p.Validator != nil {
			err := p.Validator(value)
			if err != nil {
				return fmt.Errorf("invalid value %q as %q: %w", value, p.Key, err)
			}
		}
	} else if p.IsMandatory {
		return fmt.Errorf("expected value for %q", p.Key)
	}
	return nil
}

// Validate validates an already set value
func (p *Param) Validate() error {
	return p.PreValidate(p.String())
}

func (p *Params) AddParam(key, value string) {
	*p = append(*p, &Param{
		Key:      key,
		value:    value,
		assigned: true,
	})
}

func (p *Params) ParamMap() (res ParamMap) {
	res = make(ParamMap)
	for _, v := range *p {
		res[v.Key] = v.String()
	}
	return
}

func (p *Params) Validate() error {
	for _, param := range *p {
		if err := param.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Get returns the value of the parameter with the given key or an empty string
func (p *Params) Get(key string) string {
	for _, param := range *p {
		if key == param.Key {
			return param.String()
		}
	}
	return ""
}

func (p *Params) ValidateStringMap(cfg map[string]string) error {
	for _, param := range *p {
		if value, ok := cfg[param.Key]; ok {
			if param.Validator != nil {
				err := param.Validator(value)
				if err != nil {
					return fmt.Errorf("invalid value %q as %q: %w", value, param.Key, err)
				}
			}
		} else if param.IsMandatory {
			return fmt.Errorf("expected value for %q", param.Key)
		}
	}
	return nil
}

func (p *Param) String() string {
	if p == nil {
		return ""
	}
	if p.assigned {
		return p.value
	}
	return p.DefaultValue
}

func (p *Param) Set(val string) error {
	if p.Validator != nil {
		err := p.Validator(val)
		if err != nil {
			return err
		}
	}
	p.assigned = true
	p.value = val
	return nil
}

func (p *Param) Type() string {
	return "string"
}

func ParamMapFromParams(p Params) map[string]*Param {
	res := make(map[string]*Param)
	for _, param := range p {
		res[param.Key] = param
	}
	return res
}
