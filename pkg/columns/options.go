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

package columns

import "github.com/kinvolk/inspektor-gadget/pkg/columns/ellipsis"

type Option func(*Options)

type Options struct {
	DefaultAlignment Alignment             // default text alignment to use
	DefaultEllipsis  ellipsis.EllipsisType // default type of ellipsis to use for overflowing text
	DefaultWidth     int                   // width to be used when no width is specified for a column
}

func GetDefault() *Options {
	return &Options{
		DefaultAlignment: AlignLeft,
		DefaultEllipsis:  ellipsis.End,
		DefaultWidth:     16,
	}
}

// WithAlignment sets the default alignment
func WithAlignment(a Alignment) Option {
	return func(opts *Options) {
		opts.DefaultAlignment = a
	}
}

// WithEllipsis sets the default ellipsis type
func WithEllipsis(e ellipsis.EllipsisType) Option {
	return func(opts *Options) {
		opts.DefaultEllipsis = e
	}
}

// WithWidth sets the default column width
func WithWidth(w int) Option {
	return func(opts *Options) {
		opts.DefaultWidth = w
	}
}
