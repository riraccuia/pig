package icmp

import (
	"math"
	"testing"
	"time"
)

func TestCalculateUsed(t *testing.T) {
	tests := []struct {
		name     string
		readPos  uint64
		writePos uint64
		size     int
		expected int
	}{
		// Basic cases
		{"empty buffer", 0, 0, 1000, 0},
		{"normal case", 100, 300, 1000, 200},
		{"full buffer", 100, 1100, 1000, 1000},
		{"overfull buffer", 100, 2100, 1000, 1000},

		// Wraparound cases
		{"buffer wraparound", 800, 200, 1000, 400},
		{"minimal wraparound", 999, 1, 1000, 2},
		{"same modulo empty", 12345, 12345, 1000, 0},
		{"same modulo full", 1000, 2000, 1000, 1000},

		// uint64 overflow cases
		{"uint64 wraparound", math.MaxUint64 - 199, 100, 1000, 684},
		{"max uint64 edge", math.MaxUint64 - 1, 1, 1000, 387},
		{"large counters", math.MaxUint64 / 2, math.MaxUint64/2 + 500, 1000, 500},

		// Small buffer edge cases
		{"small buffer wraparound", 10, 5, 8, 8}, // Should cap at buffer size
		{"small buffer normal", 2, 5, 8, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &buffer{
				readPos:  tt.readPos,
				writePos: tt.writePos,
				size:     tt.size,
			}

			result := b.calculateUsed()
			if result != tt.expected {
				t.Errorf("calculateUsed() = %d, want %d (readPos=%d, writePos=%d, size=%d)",
					result, tt.expected, tt.readPos, tt.writePos, tt.size)
			}

			// Verify result is within bounds
			if result < 0 || result > tt.size {
				t.Errorf("calculateUsed() = %d is out of bounds [0, %d]", result, tt.size)
			}
		})
	}
}

func TestBufferWriteReadWraparound(t *testing.T) {
	b := newBuffer(10) // Small buffer for easy testing

	// Fill buffer to near end
	data1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	n, err := b.Write(data1)
	if err != nil || n != 8 {
		t.Fatalf("Write failed: n=%d, err=%v", n, err)
	}

	// Read some data to make space
	buf := make([]byte, 5)
	n, err = b.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("Read failed: n=%d, err=%v", n, err)
	}

	// Verify read data
	expected := []byte{1, 2, 3, 4, 5}
	for i, v := range expected {
		if buf[i] != v {
			t.Errorf("Read data[%d] = %d, want %d", i, buf[i], v)
		}
	}

	// Write data that will wrap around
	data2 := []byte{9, 10, 11, 12, 13}
	n, err = b.Write(data2)
	if err != nil || n != 5 {
		t.Fatalf("Wraparound write failed: n=%d, err=%v", n, err)
	}

	// Read all remaining data
	buf = make([]byte, 8)
	n, err = b.Read(buf)
	if err != nil || n != 8 {
		t.Fatalf("Final read failed: n=%d, err=%v", n, err)
	}

	// Verify wraparound data
	expected = []byte{6, 7, 8, 9, 10, 11, 12, 13}
	for i, v := range expected {
		if buf[i] != v {
			t.Errorf("Wraparound data[%d] = %d, want %d", i, buf[i], v)
		}
	}
}

func TestBufferCopyBounds(t *testing.T) {
	b := newBuffer(8)

	// Fill buffer to position 6 to test wraparound
	initialData := []byte{1, 2, 3, 4, 5, 6}
	n, err := b.Write(initialData)
	if err != nil || n != 6 {
		t.Fatalf("Initial write failed: n=%d, err=%v", n, err)
	}

	// Read first 4 bytes to make space and move readPos
	buf := make([]byte, 4)
	n, err = b.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("Initial read failed: n=%d, err=%v", n, err)
	}

	// Now write data that will wrap around
	wrapData := []byte{7, 8, 9, 10}
	n, err = b.Write(wrapData)
	if err != nil || n != 4 {
		t.Fatalf("Wraparound write failed: n=%d, err=%v", n, err)
	}

	// Read all remaining data to test wraparound copy bounds
	buf = make([]byte, 6)
	n, err = b.Read(buf)
	if err != nil || n != 6 {
		t.Fatalf("Wraparound read failed: n=%d, err=%v", n, err)
	}

	// Verify data integrity: should be [5, 6, 7, 8, 9, 10]
	expected := []byte{5, 6, 7, 8, 9, 10}
	for i, v := range expected {
		if buf[i] != v {
			t.Errorf("Data mismatch at %d: got %d, want %d", i, buf[i], v)
		}
	}
}

func TestBufferLargeCounters(t *testing.T) {
	b := newBuffer(100)

	// Simulate large counter values
	b.readPos = math.MaxUint64 - 50
	b.writePos = 50 // Wrapped around

	used := b.calculateUsed()
	if used < 0 || used > 100 {
		t.Errorf("Large counter calculateUsed() = %d, should be in [0, 100]", used)
	}

	// Test that modulo arithmetic works correctly
	readIdx := int(b.readPos % uint64(b.size))
	writeIdx := int(b.writePos % uint64(b.size))
	if readIdx < 0 || readIdx >= 100 || writeIdx < 0 || writeIdx >= 100 {
		t.Errorf("Modulo indices out of bounds: readIdx=%d, writeIdx=%d", readIdx, writeIdx)
	}
}

func TestBufferEmpty(t *testing.T) {
	b := newBuffer(100)

	if b.Len() != 0 {
		t.Errorf("New buffer should be empty, got Len() = %d", b.Len())
	}

	// Test reading from empty buffer (should block, so we test with zero timeout)
	buf := make([]byte, 10)
	b.SetReadDeadline(time.Now()) // Immediate timeout
	n, err := b.Read(buf)
	if n != 0 || err == nil {
		t.Errorf("Reading from empty buffer should fail: n=%d, err=%v", n, err)
	}
}

/*func TestBufferFull(t *testing.T) {
	b := newBuffer(5)

	// Fill buffer completely
	data := []byte{1, 2, 3, 4, 5}
	n, err := b.Write(data)
	if err != nil || n != 5 {
		t.Fatalf("Fill buffer failed: n=%d, err=%v", n, err)
	}

	if b.Len() != 5 {
		t.Errorf("Full buffer Len() = %d, want 5", b.Len())
	}

	// Try to write more (should block, test with timeout)
	b.SetWriteDeadline(time.Now()) // Immediate timeout
	n, err = b.Write([]byte{6})
	if n != 0 || err == nil {
		t.Errorf("Writing to full buffer should fail: n=%d, err=%v", n, err)
	}
}*/

func TestBufferReset(t *testing.T) {
	b := newBuffer(10)

	// Add some data
	data := []byte{1, 2, 3}
	b.Write(data)

	if b.Len() == 0 {
		t.Error("Buffer should have data before reset")
	}

	// Reset buffer
	b.Reset()

	if b.Len() != 0 {
		t.Errorf("Buffer should be empty after reset, got Len() = %d", b.Len())
	}

	if b.readPos != 0 || b.writePos != 0 {
		t.Errorf("Positions should be zero after reset: readPos=%d, writePos=%d",
			b.readPos, b.writePos)
	}
}
