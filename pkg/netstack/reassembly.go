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

// oooSegment is out-of-order data held until the gap before it is filled.
type oooSegment struct {
	seq  uint32
	data []byte
	fin  bool
}

// reassemblyQueue keeps out-of-order segments sorted by sequence number.
type reassemblyQueue struct {
	segs []oooSegment
}

func (q *reassemblyQueue) empty() bool { return len(q.segs) == 0 }

func (q *reassemblyQueue) clear() { q.segs = nil }

// insert stores a copy of data, skipping segments already fully queued.
func (q *reassemblyQueue) insert(seq uint32, data []byte, fin bool) {
	i := 0
	for i < len(q.segs) && seqLE(q.segs[i].seq, seq) {
		existing := q.segs[i]
		if existing.seq == seq && len(existing.data) >= len(data) && (existing.fin || !fin) {
			return
		}
		i++
	}
	seg := oooSegment{seq: seq, data: append([]byte(nil), data...), fin: fin}
	q.segs = append(q.segs, oooSegment{})
	copy(q.segs[i+1:], q.segs[i:])
	q.segs[i] = seg
}

// popReady returns the next segment that starts at or before rcvNxt, trimmed
// so that it begins exactly at rcvNxt. Segments that are entirely old are dropped.
func (q *reassemblyQueue) popReady(rcvNxt uint32) (oooSegment, bool) {
	for len(q.segs) > 0 {
		seg := q.segs[0]
		if seqGT(seg.seq, rcvNxt) {
			return oooSegment{}, false
		}
		q.segs[0] = oooSegment{}
		q.segs = q.segs[1:]
		end := seg.seq + uint32(len(seg.data))
		if seqLT(end, rcvNxt) || (end == rcvNxt && !seg.fin) {
			continue
		}
		seg.data = seg.data[rcvNxt-seg.seq:]
		seg.seq = rcvNxt
		return seg, true
	}
	return oooSegment{}, false
}
