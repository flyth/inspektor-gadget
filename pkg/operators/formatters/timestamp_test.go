// Copyright 2024 The Inspektor Gadget authors
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

package formatters

import (
	"testing"
	"time"
)

// TestAppendTimestampMatchesStdlib asserts the hand-rolled formatter is
// byte-for-byte identical to time.AppendFormat with the default layout.
func TestAppendTimestampMatchesStdlib(t *testing.T) {
	zones := []*time.Location{
		time.UTC,
		time.FixedZone("CEST", 2*3600),
		time.FixedZone("IST", 5*3600+30*60), // half-hour offset
		time.FixedZone("NPT", 5*3600+45*60), // 45-minute offset
		time.FixedZone("west", -8*3600),
		time.FixedZone("oddsec", 7*3600+13), // seconds in offset, truncated to minutes
	}
	// nanoseconds spanning zero, small, and max to exercise zero-padding.
	nanos := []int{0, 1, 7, 123, 999999999, 100000000, 42}
	base := time.Date(2026, 6, 26, 14, 5, 9, 0, time.UTC).Unix()
	offsets := []int64{0, 1, 86399, -1, 1735689600 - base, 999999999}

	for _, z := range zones {
		for _, off := range offsets {
			for _, ns := range nanos {
				tm := time.Unix(base+off, int64(ns)).In(z)
				if tm.Year() > 9999 || tm.Year() < 0 {
					continue
				}
				want := tm.AppendFormat(nil, defaultTimestampFormat)
				got := appendTimestampRFC3339Nano9(nil, tm)
				if string(got) != string(want) {
					t.Fatalf("zone=%v off=%d ns=%d\n got=%q\nwant=%q", z, off, ns, got, want)
				}
			}
		}
	}
}
