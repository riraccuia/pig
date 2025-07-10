package icmp

import (
	"fmt"
	"sync"
	"time"
)

// buffer provides a thread-safe fixed-size circular buffer
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
	b.rcond = sync.NewCond(&b.mu)
	b.wcond = sync.NewCond(&b.mu)
	return b
}

// calculateUsed returns the number of bytes currently used in the buffer
func (b *buffer) calculateUsed() int {
	// Check if buffer is empty first
	if b.writePos == b.readPos {
		return 0
	}

	// Handle the simple case first to avoid modulo when possible
	if b.writePos > b.readPos {
		diff := b.writePos - b.readPos
		if diff <= uint64(b.size) {
			return int(diff)
		}
		// If diff > size, buffer is full
		return b.size
	}

	// Wraparound case: writePos < readPos due to uint64 overflow
	// Calculate how much data spans the wraparound
	readIdx := int(b.readPos % uint64(b.size))
	writeIdx := int(b.writePos % uint64(b.size))

	// In wraparound case, buffer contains data from readIdx to end + start to writeIdx
	used := writeIdx + (b.size - readIdx)
	// Ensure result doesn't exceed buffer size
	if used > b.size {
		return b.size
	}
	return used
}

// calculateAvailable returns the number of bytes available for writing
func (b *buffer) calculateAvailable() int {
	return b.size - b.calculateUsed()
}

// Write copies data into the buffer
func (b *buffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}

	b.mu.Lock()

	// Calculate available space with correct wraparound handling
	used := b.calculateUsed()
	available := b.size - used
	/*if used >= b.size || available < len(data) {
		b.mu.Unlock()
		// dropping silently
		return len(data), nil
	}*/
	for used >= b.size || available < len(data) {
		b.wcond.Wait()
		used = b.calculateUsed()
		available = b.size - used
	}

	isEmpty := b.writePos == b.readPos

	writeLen := len(data)
	if writeLen > available {
		writeLen = available
	}

	// Calculate write position and handle wraparound
	idx := int(b.writePos % uint64(b.size))
	remaining := b.size - idx // Space until end of buffer

	if remaining >= writeLen {
		// Simple case - no wraparound needed
		copy(b.data[idx:idx+writeLen], data[:writeLen])
	} else {
		// Wraparound case - split the copy
		copy(b.data[idx:], data[:remaining])
		copy(b.data[0:writeLen-remaining], data[remaining:writeLen])
	}

	b.writePos += uint64(writeLen)

	if isEmpty {
		b.rcond.Signal()
	}

	b.mu.Unlock()
	return writeLen, nil
}

// Read copies data from the buffer
func (b *buffer) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()

	if isDeadlineExceeded(b.readDeadline) {
		b.mu.Unlock()
		return 0, fmt.Errorf("read deadline exceeded")
	}

	// Wait for data
	for b.writePos == b.readPos {
		if isDeadlineExceeded(b.readDeadline) {
			b.mu.Unlock()
			return 0, fmt.Errorf("read deadline exceeded")
		}
		b.rcond.Wait()
	}

	// Calculate available data with correct wraparound handling
	available := b.calculateUsed()
	if available > len(p) {
		available = len(p)
	}

	// Calculate read position and handle wraparound
	idx := int(b.readPos % uint64(b.size))
	remaining := b.size - idx // Space until end of buffer

	if remaining >= available {
		// Simple case - no wraparound needed
		copy(p[:available], b.data[idx:idx+available])
	} else {
		// Wraparound case - split the copy
		copy(p[:remaining], b.data[idx:])
		wrapLen := available - remaining
		if wrapLen > 0 {
			copy(p[remaining:remaining+wrapLen], b.data[0:wrapLen])
		}
	}

	b.readPos += uint64(available)

	b.wcond.Signal()
	b.mu.Unlock()
	return available, nil
}

// Reset clears the buffer
func (b *buffer) Reset() {
	b.mu.Lock()
	b.readPos = 0
	b.writePos = 0
	b.rcond.Broadcast()
	b.wcond.Broadcast()
	b.mu.Unlock()
}

// Len returns the number of bytes currently in the buffer
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
