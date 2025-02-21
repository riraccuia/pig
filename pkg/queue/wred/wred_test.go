package wred

import (
	"testing"
)

func TestWRED(t *testing.T) {
	wred, err := NewWRED(9)
	if err != nil {
		t.Fatalf("Failed to create WRED: %v", err)
	}
	queueLengths := []int{10, 10, 10, 10000, 10, 10, 10, 10, 10, 10}
	for _, queueLength := range queueLengths {
		wred.Update(float64(queueLength))
	}
	if int(wred.GetAvgLen()) != 10 {
		t.Errorf("Expected avg queue length to be 10, got %f", wred.GetAvgLen())
		return
	}
	t.Logf("Avg queue length: %f", wred.GetAvgLen())
}
