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

package benchmark

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"sort"
	"strconv"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/filter"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/group"
	refsort "github.com/kinvolk/inspektor-gadget/pkg/columns/sort"
)

type TestStruct struct {
	Int      int    `column:"int" json:"int"`
	Int2     int    `column:"int2" json:"int2"`
	Int3     int    `column:"int3" json:"int3"`
	Int4     int    `column:"int4" json:"int4"`
	String   string `column:"string" json:"string"`
	String2  string `column:"string2" json:"string2"`
	String3  string `column:"string3" json:"string3"`
	String4  string `column:"string4" json:"string4"`
	GroupID1 string `column:"groupID1" json:"groupID1"`
	GroupID2 string `column:"groupID2" json:"groupID2"`
}

var data []*TestStruct

func init() {
	for i := 0; i < 1000; i++ {
		b := make([]byte, 32)
		rand.Read(b)
		hx := hex.EncodeToString(b)
		data = append(data, &TestStruct{
			Int:      rand.Intn(65535),
			Int2:     rand.Intn(65535),
			Int3:     rand.Intn(65535),
			Int4:     rand.Intn(65535),
			String:   hx[0:16],
			String2:  hx[16:32],
			String3:  hx[32:48],
			String4:  hx[48:],
			GroupID1: strconv.Itoa(i % 100),
			GroupID2: strconv.Itoa(i % 10),
		})
	}
}

func BenchmarkFilterNumberGte(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "int:>32000")
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterNumberEq(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "int:32000")
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterNumberNeq(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "int:!32000")
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterStringEq(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "string:"+data[0].String)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterStringNeq(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "string:!"+data[0].String)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterStringRegex(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "string:~"+data[0].String[1:5])
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkFilterStringRegexCI(b *testing.B) {
	cl := 0
	cols := columns.MustCreateColumns[TestStruct]()

	intFilter, err := filter.GetFilterFromString(cols.GetColumnMap(), "string:~(?i)"+data[0].String[1:5])
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	for n := 0; n < b.N; n++ {
		if !intFilter.Match(data[n%len(data)]) {
			continue
		}
		cl++
	}
}

func BenchmarkGroup1000to100(b *testing.B) {
	cols := columns.MustCreateColumns[TestStruct]()

	for n := 0; n < b.N; n++ {
		x, _ := group.GroupEntries(cols.GetColumnMap(), data, []string{"groupID1"})
		if len(x) == 0 {
			b.Logf("empty")
		}
	}
}

func BenchmarkGroup1000to10(b *testing.B) {
	cols := columns.MustCreateColumns[TestStruct]()

	for n := 0; n < b.N; n++ {
		x, _ := group.GroupEntries(cols.GetColumnMap(), data, []string{"groupID2"})
		if len(x) == 0 {
			b.Logf("empty")
		}
	}
}

func BenchmarkSortReflection1000(b *testing.B) {
	cols := columns.MustCreateColumns[TestStruct]()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		// Presort randomly
		rand.Seed(1)
		rand.Shuffle(len(data), func(i, j int) { data[i], data[j] = data[j], data[i] })
		b.StartTimer()

		refsort.SortEntries(cols.GetColumnMap(), data, []string{"int"})
	}
}

func BenchmarkSortNative1000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		// Presort randomly
		rand.Seed(1)
		rand.Shuffle(len(data), func(i, j int) { data[i], data[j] = data[j], data[i] })
		b.StartTimer()

		sort.SliceStable(data, func(i, j int) bool {
			return data[i].Int < data[j].Int
		})
	}
}

func BenchmarkJSON(b *testing.B) {
	for n := 0; n < b.N; n++ {
		json.Marshal(data[n%len(data)])
	}
}
