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

package icmp

import (
	"fmt"
	"sync"
	"time"
)

var errBufferClosed = fmt.Errorf("buffer closed")

// buffer provides a thread-safe fixed-size circular buffer.
type buffer struct {
	mu            sync.Mutex
	rcond         *sync.Cond
	wcond         *sync.Cond
	data          []byte
	size          int
	readPos       uint64
	writePos      uint64
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
}

// newBuffer creates a new buffer with the specified size.
func newBuffer(size int) *buffer {
	if size <= 0 {
		size = 64 * 1024 // Ensure minimum buffer size
	}
	b := &buffer{
		data: make([]byte, size),
		size: size,
	}
	b.rcond = sync.NewCond(&b.mu)
	b.wcond = sync.NewCond(&b.mu)
	return b
}

func (b *buffer) calculateUsed() int {
	used := b.writePos - b.readPos
	if used > uint64(b.size) {
		return b.size
	}
	return int(used)
}

func (b *buffer) copyIn(pos uint64, src []byte) int {
	idx := int(pos % uint64(b.size))
	n := copy(b.data[idx:], src)
	if n < len(src) {
		n += copy(b.data, src[n:])
	}
	return n
}

func (b *buffer) copyOut(pos uint64, dst []byte) {
	idx := int(pos % uint64(b.size))
	n := copy(dst, b.data[idx:])
	if n < len(dst) {
		copy(dst[n:], b.data)
	}
}

// Write copies data into the buffer.
func (b *buffer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	copied := 0
	for copied < len(data) {
		if b.closed {
			return copied, errBufferClosed
		}
		if b.size == b.calculateUsed() {
			b.wcond.Wait()
			continue
		}
		avail := b.size - b.calculateUsed()
		wasEmpty := avail == b.size
		chunk := data[copied:]
		if len(chunk) > avail {
			chunk = chunk[:avail]
		}
		n := b.copyIn(b.writePos, chunk)
		b.writePos += uint64(n)
		copied += n
		if wasEmpty {
			b.rcond.Signal()
		}
	}
	return copied, nil
}

// Read copies data from the buffer.
func (b *buffer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.calculateUsed() == 0 {
		if b.closed {
			return 0, errBufferClosed
		}
		if isDeadlineExceeded(b.readDeadline) {
			return 0, fmt.Errorf("read deadline exceeded")
		}
		b.rcond.Wait()
	}
	n := b.calculateUsed()
	if n > len(p) {
		n = len(p)
	}
	b.copyOut(b.readPos, p[:n])
	b.readPos += uint64(n)
	b.wcond.Signal()
	return n, nil
}

// Close closes the buffer.
func (b *buffer) Close() {
	b.mu.Lock()
	b.closed = true
	//b.readPos = 0
	//b.writePos = 0
	b.rcond.Broadcast()
	b.wcond.Broadcast()
	b.mu.Unlock()
}

// Len returns the number of bytes currently in the buffer.
func (b *buffer) Len() int {
	b.mu.Lock()
	n := b.calculateUsed()
	b.mu.Unlock()
	return n
}

func (b *buffer) SetReadDeadline(t time.Time) error {
	b.mu.Lock()
	b.readDeadline = t
	b.mu.Unlock()
	if t.Equal(time.Time{}) {
		return nil
	}
	now := time.Now()
	if now.Equal(t) || now.After(t) {
		b.rcond.Signal()
		return nil
	}
	time.AfterFunc(time.Until(t), func() {
		b.rcond.Signal()
	})
	return nil
}

func (b *buffer) SetWriteDeadline(t time.Time) error {
	/*b.mu.Lock()
	b.writeDeadline = t
	b.wcond.Signal()
	b.mu.Unlock()
	return nil*/
	return nil
}

func isDeadlineExceeded(deadline time.Time) bool {
	//if deadline.IsZero() {
	if deadline.Equal(time.Time{}) {
		return false
	}
	return time.Now().After(deadline)
}
