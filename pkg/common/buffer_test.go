package common

import "testing"

func TestGetBufferSizeTiers(t *testing.T) {
	pool := NewBufferPool()

	// Each minCap should land in the smallest tier that can hold it.
	// Values just above a tier boundary must jump to the next tier.
	cases := []struct {
		name    string
		minCap  int
		wantCap int
	}{
		{"zero", 0, BufferSize512},
		{"one byte", 1, BufferSize512},
		{"exact 512", BufferSize512, BufferSize512},
		{"just over 512", BufferSize512 + 1, BufferSize1024},
		{"exact 1024", BufferSize1024, BufferSize1024},
		{"just over 1024", BufferSize1024 + 1, BufferSize2048},
		{"exact 2048", BufferSize2048, BufferSize2048},
		{"just over 2048", BufferSize2048 + 1, BufferSize4096},
		{"exact 4096", BufferSize4096, BufferSize4096},
		{"just over 4096", BufferSize4096 + 1, BufferSize65536},
		{"exact 65536", BufferSize65536, BufferSize65536},
		// Above the largest tier: allocate exactly minCap, do not pool.
		{"above largest tier", BufferSize65536 + 1, BufferSize65536 + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := pool.GetBuffer(tc.minCap)
			if cap(b) != tc.wantCap {
				t.Fatalf("cap = %d, want %d (minCap %d)", cap(b), tc.wantCap, tc.minCap)
			}
		})
	}
}

func TestPutBuffer(t *testing.T) {
	pool := NewBufferPool()

	cases := []struct {
		name string
		buf  []byte
	}{
		{"nil", nil},
		// Too small for any tier — Put should ignore it, not panic.
		{"smaller than 512", make([]byte, 64)},
		{"exact 512", make([]byte, BufferSize512)},
		{"exact 65536", make([]byte, BufferSize65536)},
		// Larger than the top tier still goes into the top pool on Put.
		{"larger than 65536", make([]byte, BufferSize65536*2)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool.PutBuffer(tc.buf)
		})
	}
}
