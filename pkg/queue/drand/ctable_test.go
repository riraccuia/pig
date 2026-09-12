package drand

import (
	"testing"
)

func TestCondensedTable(t *testing.T) {
	ct := NewCondensedTable([]any{0, 1}, []float64{0.25, 0.75})
	counts := make(map[int]int)
	for i := 0; i < 10000; i++ {
		counts[ct.Sample().(int)]++
	}
	if counts[0] < 2000 || counts[0] > 3000 {
		t.Errorf("Sample() = %v; want %v", counts[0], 2500)
	}
	if counts[1] < 7000 || counts[1] > 8000 {
		t.Errorf("Sample() = %v; want %v", counts[1], 8500)
	}
}
