// Copyright 2026 Riccardo Raccuia
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

package netstack

import "encoding/binary"

const (
	optEnd    = 0
	optNOP    = 1
	optMSS    = 2 // RFC 9293 §3.2
	optWScale = 3 // RFC 7323 §2.2

	optMSSLen    = 4
	optWScaleLen = 3
)

// tcpOptions holds the options this stack understands; others are skipped.
type tcpOptions struct {
	mss       uint16
	hasMSS    bool
	wscale    uint8
	hasWScale bool
}

func parseOptions(b []byte) tcpOptions {
	var opts tcpOptions
	for i := 0; i < len(b); {
		kind := b[i]
		if kind == optEnd {
			return opts
		}
		if kind == optNOP {
			i++
			continue
		}
		if i+1 >= len(b) {
			return opts
		}
		length := int(b[i+1])
		if length < 2 || i+length > len(b) {
			return opts
		}
		if kind == optMSS && length == optMSSLen {
			opts.mss = binary.BigEndian.Uint16(b[i+2 : i+4])
			opts.hasMSS = true
		}
		if kind == optWScale && length == optWScaleLen {
			opts.wscale = b[i+2]
			opts.hasWScale = true
		}
		i += length
	}
	return opts
}

// encodedLen is a multiple of 4: window scale is padded with a leading NOP.
func (o tcpOptions) encodedLen() int {
	n := 0
	if o.hasMSS {
		n += optMSSLen
	}
	if o.hasWScale {
		n += 1 + optWScaleLen
	}
	return n
}

func (o tcpOptions) encode(b []byte) {
	i := 0
	if o.hasMSS {
		b[0] = optMSS
		b[1] = optMSSLen
		binary.BigEndian.PutUint16(b[2:4], o.mss)
		i = optMSSLen
	}
	if o.hasWScale {
		b[i] = optNOP
		b[i+1] = optWScale
		b[i+2] = optWScaleLen
		b[i+3] = o.wscale
	}
}
