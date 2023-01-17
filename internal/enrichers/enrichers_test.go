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

package enrichers

import "testing"

type Enricher1 struct {
	Enricher
}

func (e *Enricher1) Name() string {
	return "enricher1"
}

func (e *Enricher1) Dependencies() []string {
	return nil
}

type Enricher2 struct {
	Enricher
}

func (e *Enricher2) Name() string {
	return "enricher2"
}

func (e *Enricher2) Dependencies() []string {
	return []string{"enricher1"}
}

type Enricher3 struct {
	Enricher
}

func (e *Enricher3) Name() string {
	return "enricher3"
}

func (e *Enricher3) Dependencies() []string {
	return []string{"enricher2"}
}

func TestSortEnrichers(t *testing.T) {
	e1 := &Enricher1{}
	e2 := &Enricher2{}
	e3 := &Enricher3{}
	e := Enrichers{e3, e2, e1}
	t.Logf("0: %s", e[0].Name())
	t.Logf("1: %s", e[1].Name())
	t.Logf("2: %s", e[2].Name())

	e, err := SortEnrichers(e)
	if err != nil {
		t.Fatalf("didn't expect error, got %v", err)
	}
	if len(e) != 3 {
		t.Fatalf("expected 3 entries")
	}
	if e[0] != e1 || e[1] != e2 || e[2] != e3 {
		t.Errorf("expected order: e1, e2, got: %+v", e)
		t.Logf("0: %s", e[0].Name())
		t.Logf("1: %s", e[1].Name())
		t.Logf("2: %s", e[2].Name())
	}
}
