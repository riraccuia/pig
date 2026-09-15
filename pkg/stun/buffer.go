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

package stun

import "bytes"

// SerializeBuffer is a helper used to write stun messages to the wire.
// It is inspired by the [github.com/google/gopacket/layers.SerializeBuffer] interface,
// although the implementation differs.
type SerializeBuffer interface {
	// Len returns the number of bytes written to the buffer.
	Len() int
	// Append appends n bytes to the buffer and returns a slice of the appended bytes
	// for the caller to write to. The caller must write exactly n bytes to the
	// returned slice.
	Append(n int) []byte
	// Bytes returns a slice of the buffer's contents.
	Bytes() []byte
	// Reset clears the buffer and resets the written position to 0.
	Reset()
}

// Buffer is a simple buffer that can be used to write STUN messages to.
// It implements the [SerializeBuffer] interface.
// This implementation mimics the behavior of [bytes.Buffer], but allows the caller to directly access the
// requested portion of the buffer. The benefit is the ability to write raw binary data directly and reduce allocations.
// Buffer is not thread-safe.
type Buffer struct {
	buf     []byte
	written int
}

// Len returns the number of bytes written to the buffer.
func (b *Buffer) Len() int {
	return b.written
}

// NewBuffer creates a new Buffer from a byte slice, preserving its contents and
// setting the written position to len(buf).
// Use [Buffer.Reset] to clear the buffer and reset the written position.
func NewBuffer(buf []byte) *Buffer {
	return &Buffer{
		buf:     buf,
		written: len(buf),
	}
}

// Append appends n bytes to the buffer and returns a slice of the appended bytes
// for the caller to write to. The caller must write exactly n bytes to the
// returned slice.
func (b *Buffer) Append(n int) []byte {
	b.grow(n)
	start := b.written
	b.written += n
	return b.buf[start:b.written]
}

// Bytes returns a slice of the buffer's contents, up to the written position.
// The returned slice is not a copy, and could be modified directly if needed.
func (b *Buffer) Bytes() []byte {
	return b.buf[:b.written]
}

// Reset resets the written position to 0, but keeps the underlying buffer, without
// zeroing the bytes.
func (b *Buffer) Reset() {
	b.written = 0
	b.buf = b.buf[:0]
}

// Zero calls Reset() and then clears the buffer up to its capacity, zeroing all the bytes.
func (b *Buffer) Zero() {
	b.Reset()
	clear(b.buf[:cap(b.buf)])
}

// grow grows the buffer by n bytes.
func (b *Buffer) grow(n int) {
	// try to grow by reslicing
	if b.written+n <= cap(b.buf) {
		b.buf = b.buf[:b.written+n]
		return
	}
	// not enough space, so grow by allocating a new slice and copying the data
	b.buf = growSlice(b.buf, n)[:b.written+n]
}

// growSlice grows b by n, preserving the original content of b.
// If the allocation fails, it panics with ErrTooLarge.
func growSlice(b []byte, n int) []byte {
	defer func() {
		if recover() != nil {
			panic(bytes.ErrTooLarge)
		}
	}()
	// TODO(http://golang.org/issue/51462): We should rely on the append-make
	// pattern so that the compiler can call runtime.growslice. For example:
	//	return append(b, make([]byte, n)...)
	// This avoids unnecessary zero-ing of the first len(b) bytes of the
	// allocated slice, but this pattern causes b to escape onto the heap.
	//
	// Instead use the append-make pattern with a nil slice to ensure that
	// we allocate buffers rounded up to the closest size class.
	c := len(b) + n
	// The growth rate has historically always been 2x. In the future,
	// we could rely purely on append to determine the growth rate.
	c = max(c, 2*cap(b))
	b2 := append([]byte(nil), make([]byte, c)...)
	i := copy(b2, b)
	return b2[:i]
}
