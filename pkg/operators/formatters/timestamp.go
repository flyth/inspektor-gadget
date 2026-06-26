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

import "time"

// defaultTimestampFormat is the RFC3339 layout with a fixed nine-digit
// fractional second. It is the default for the timestamp formatter.
const defaultTimestampFormat = "2006-01-02T15:04:05.000000000Z07:00"

// appendTimestampRFC3339Nano9 appends t formatted as defaultTimestampFormat.
//
// time.Time.AppendFormat re-parses the layout string on every call (via
// time.nextStdChunk) and, because the nine-digit fractional second is not the
// trimming RFC3339Nano constant, misses the stdlib RFC3339 fast path. On the
// per-event hot path that costs ~6% of CPU. This writes the fixed-width fields
// directly. Output is byte-for-byte identical to
// t.AppendFormat(b, defaultTimestampFormat) for years in [0,9999]; callers must
// fall back to AppendFormat for a custom format or out-of-range year.
func appendTimestampRFC3339Nano9(b []byte, t time.Time) []byte {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	nsec := t.Nanosecond()

	b = appendPad(b, year, 4)
	b = append(b, '-')
	b = appendPad(b, int(month), 2)
	b = append(b, '-')
	b = appendPad(b, day, 2)
	b = append(b, 'T')
	b = appendPad(b, hour, 2)
	b = append(b, ':')
	b = appendPad(b, min, 2)
	b = append(b, ':')
	b = appendPad(b, sec, 2)
	b = append(b, '.')
	b = appendPad(b, nsec, 9)

	_, offset := t.Zone()
	if offset == 0 {
		return append(b, 'Z')
	}
	if offset < 0 {
		b = append(b, '-')
		offset = -offset
	} else {
		b = append(b, '+')
	}
	offMin := offset / 60 // Z07:00 truncates to minutes, matching the stdlib layout.
	b = appendPad(b, offMin/60, 2)
	b = append(b, ':')
	b = appendPad(b, offMin%60, 2)
	return b
}

// appendPad appends v as a zero-padded decimal of at least width digits.
func appendPad(b []byte, v, width int) []byte {
	var tmp [20]byte
	i := len(tmp)
	for v >= 10 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	i--
	tmp[i] = byte('0' + v)
	for n := len(tmp) - i; n < width; n++ {
		b = append(b, '0')
	}
	return append(b, tmp[i:]...)
}
