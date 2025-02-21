package icmp

import (
	"io"
	"sync"
)

// buffer provides a thread-safe fixed-size circular buffer
type buffer struct {
	mu       sync.Mutex
	cond     *sync.Cond
	data     []byte
	size     int
	readPos  int
	writePos int
}

// newBuffer creates a new buffer with the specified size
func newBuffer(size int) *buffer {
	if size <= 0 {
		size = 64 * 1024 // Ensure minimum buffer size
	}
	b := &buffer{
		data: make([]byte, size),
		size: size,
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Write copies data into the buffer
func (b *buffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}

	b.mu.Lock()

	// Calculate available space
	used := b.writePos - b.readPos
	if used >= b.size {
		b.mu.Unlock()
		return 0, io.ErrShortWrite
	}

	available := b.size - used
	writeLen := len(data)
	if writeLen > available {
		writeLen = available
	}

	// Calculate write position and handle wraparound
	idx := b.writePos % b.size
	remaining := b.size - idx // Space until end of buffer

	if remaining >= writeLen {
		// Simple case - no wraparound needed
		copy(b.data[idx:idx+writeLen], data[:writeLen])
	} else {
		// Wraparound case - split the copy
		copy(b.data[idx:], data[:remaining])
		copy(b.data[0:writeLen-remaining], data[remaining:writeLen])
	}

	b.writePos += writeLen
	b.cond.Signal()
	b.mu.Unlock()

	return writeLen, nil
}

// Read copies data from the buffer
func (b *buffer) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()

	// Wait for data
	for b.writePos == b.readPos {
		b.cond.Wait()
	}

	// Calculate available data
	available := b.writePos - b.readPos
	if available > len(p) {
		available = len(p)
	}

	// Calculate read position and handle wraparound
	idx := b.readPos % b.size
	remaining := b.size - idx // Space until end of buffer

	if remaining >= available {
		// Simple case - no wraparound needed
		copy(p[:available], b.data[idx:idx+available])
	} else {
		// Wraparound case - split the copy
		copy(p[:remaining], b.data[idx:])
		copy(p[remaining:available], b.data[0:available-remaining])
	}

	b.readPos += available
	b.mu.Unlock()
	return available, nil
}

// Reset clears the buffer
func (b *buffer) Reset() {
	b.mu.Lock()
	b.readPos = 0
	b.writePos = 0
	b.cond.Broadcast()
	b.mu.Unlock()
}

// Len returns the number of bytes currently in the buffer
func (b *buffer) Len() int {
	b.mu.Lock()
	n := b.writePos - b.readPos
	b.mu.Unlock()
	return n
}
