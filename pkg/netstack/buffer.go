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

// ringBuffer is a fixed-capacity byte FIFO. It is not safe for concurrent use;
// callers hold the owning Conn's mutex.
type ringBuffer struct {
	data []byte
	head int
	size int
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{data: make([]byte, max(capacity, 1))}
}

func (r *ringBuffer) Len() int  { return r.size }
func (r *ringBuffer) Cap() int  { return len(r.data) }
func (r *ringBuffer) Free() int { return len(r.data) - r.size }

// Write appends as much of p as fits and returns the number of bytes stored.
func (r *ringBuffer) Write(p []byte) int {
	n := min(len(p), r.Free())
	tail := (r.head + r.size) % len(r.data)
	copied := copy(r.data[tail:], p[:n])
	copy(r.data, p[copied:n])
	r.size += n
	return n
}

// Peek copies bytes starting off bytes past the head, without consuming them.
func (r *ringBuffer) Peek(off int, p []byte) int {
	if off >= r.size {
		return 0
	}
	n := min(len(p), r.size-off)
	start := (r.head + off) % len(r.data)
	copied := copy(p[:n], r.data[start:])
	copy(p[copied:n], r.data)
	return n
}

func (r *ringBuffer) Read(p []byte) int {
	n := r.Peek(0, p)
	r.Discard(n)
	return n
}

func (r *ringBuffer) Discard(n int) {
	n = min(n, r.size)
	r.head = (r.head + n) % len(r.data)
	r.size -= n
}

func (r *ringBuffer) Reset() {
	r.head = 0
	r.size = 0
}
