package wred

import (
	"math"
	"testing"
)

func TestNewWRED_Validation(t *testing.T) {
	tests := []struct {
		name            string
		qlen            int
		weight          float64
		dropProbability float64
		threshold       float64
		wantErr         bool
	}{
		{
			name:            "valid defaults-like",
			qlen:            256,
			weight:          9,
			dropProbability: 0.1,
			threshold:       0.5,
		},
		{
			name:            "weight zero not allowed",
			qlen:            100,
			weight:          0,
			dropProbability: 0.25,
			threshold:       0.3,
			wantErr:         true,
		},
		{
			name:            "negative weight",
			qlen:            100,
			weight:          -1,
			dropProbability: 0.25,
			threshold:       0.3,
			wantErr:         true,
		},
		{
			name:            "drop probability below zero",
			qlen:            100,
			weight:          5,
			dropProbability: -0.01,
			threshold:       0.3,
			wantErr:         true,
		},
		{
			name:            "drop probability above one",
			qlen:            100,
			weight:          5,
			dropProbability: 1.01,
			threshold:       0.3,
			wantErr:         true,
		},
		{
			name:            "threshold below zero",
			qlen:            100,
			weight:          5,
			dropProbability: 0.25,
			threshold:       -0.1,
			wantErr:         true,
		},
		{
			name:            "threshold above one",
			qlen:            100,
			weight:          5,
			dropProbability: 0.25,
			threshold:       1.1,
			wantErr:         true,
		},
		{
			name:            "qlen zero",
			qlen:            0,
			weight:          5,
			dropProbability: 0.25,
			threshold:       0.3,
			wantErr:         true,
		},
		{
			name:            "qlen negative",
			qlen:            -1,
			weight:          5,
			dropProbability: 0.25,
			threshold:       0.3,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWRED(tt.qlen, tt.weight, tt.dropProbability, tt.threshold)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if w == nil {
				t.Fatal("expected non-nil WRED")
			}
		})
	}
}

func TestNewWRED_Thresholds(t *testing.T) {
	const qlen = 100
	const threshold = 0.5

	w, err := NewWRED(qlen, 9, 0.1, threshold)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}

	wantMaxT := threshold * float64(qlen)          // 50
	wantMinT := math.Round(wantMaxT*0.5*100) / 100 // 25

	if w.maxT != wantMaxT {
		t.Errorf("maxT = %v, want %v", w.maxT, wantMaxT)
	}
	if w.minT != wantMinT {
		t.Errorf("minT = %v, want %v", w.minT, wantMinT)
	}
	if w.w != math.Pow(2, -9) {
		t.Errorf("w = %v, want %v", w.w, math.Pow(2, -9))
	}
}

func TestNewWRED_ThresholdZeroCollapsesMinMax(t *testing.T) {
	w, err := NewWRED(100, 9, 0.1, 0)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	if w.maxT != 0 || w.minT != 0 {
		t.Fatalf("minT=%v maxT=%v, want both 0", w.minT, w.maxT)
	}
}

func TestUpdate_EWMA(t *testing.T) {
	// weight=1, w=1/2, avg = (1-w)*avg + w*q
	w, err := NewWRED(100, 1, 0.25, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}

	w.Update(10)
	if got, want := w.GetAvgLen(), 5.0; got != want {
		t.Fatalf("after first Update(10): avg=%v, want %v", got, want)
	}

	w.Update(10)
	if got, want := w.GetAvgLen(), 7.5; got != want {
		t.Fatalf("after second Update(10): avg=%v, want %v", got, want)
	}

	w.Update(0)
	if got, want := w.GetAvgLen(), 3.75; got != want {
		t.Fatalf("after Update(0): avg=%v, want %v", got, want)
	}
}

func TestUpdate_HighWeightFiltersSpike(t *testing.T) {
	// weight=9 a single large sample barely moves avg from 0
	w, err := NewWRED(100, 9, 0.25, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}

	w.Update(10000)
	got := w.GetAvgLen()
	want := 10000.0 * w.w
	if got != want {
		t.Fatalf("avg after spike = %v, want %v", got, want)
	}
}

func TestIsDrop_MaxDPZeroNeverDrops(t *testing.T) {
	w, err := NewWRED(100, 1, 0, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.Update(100) // avg well above maxT
	for range 1000 {
		if w.IsDrop() {
			t.Fatal("IsDrop returned true with maxDP=0")
		}
	}
}

func TestIsDrop_BelowMinTNeverDrops(t *testing.T) {
	// qlen=100, threshold=0.5, maxT=50, minT=25
	w, err := NewWRED(100, 1, 1.0, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.avgQueueLen = 24.9 // just below minT
	for range 1000 {
		if w.IsDrop() {
			t.Fatalf("IsDrop returned true below minT (avg=%v minT=%v)", w.GetAvgLen(), w.minT)
		}
	}
}

func TestIsDrop_AtMaxTUsesMaxDP(t *testing.T) {
	const (
		maxDP   = 0.25
		samples = 20000
		// Allow generous slack for binomial noise.
		tolerance = 0.03
	)

	w, err := NewWRED(100, 1, maxDP, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.avgQueueLen = 50 // avg == maxT

	drops := 0
	for range samples {
		if w.IsDrop() {
			drops++
		}
	}
	rate := float64(drops) / float64(samples)
	if math.Abs(rate-maxDP) > tolerance {
		t.Fatalf("drop rate at maxT = %v, want ~%v (±%v)", rate, maxDP, tolerance)
	}
}

func TestIsDrop_AboveMaxTUsesMaxDP(t *testing.T) {
	t.Parallel()

	const (
		maxDP     = 0.5
		samples   = 20000
		tolerance = 0.03
	)

	w, err := NewWRED(100, 0, maxDP, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.Update(90) // avg > maxT → still p = maxDP (not forced drop)

	drops := 0
	for range samples {
		if w.IsDrop() {
			drops++
		}
	}
	rate := float64(drops) / float64(samples)
	if math.Abs(rate-maxDP) > tolerance {
		t.Fatalf("drop rate above maxT = %v, want ~%v (±%v)", rate, maxDP, tolerance)
	}
}

func TestIsDrop_MidRampLinearProbability(t *testing.T) {
	t.Parallel()

	// maxT=50, minT=25, maxDP=0.4
	// avg=37.5 → halfway → p = 0.4 * 0.5 = 0.2
	const (
		maxDP     = 0.4
		wantP     = 0.2
		samples   = 30000
		tolerance = 0.03
	)

	w, err := NewWRED(100, 0, maxDP, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.Update(37.5)

	drops := 0
	for range samples {
		if w.IsDrop() {
			drops++
		}
	}
	rate := float64(drops) / float64(samples)
	if math.Abs(rate-wantP) > tolerance {
		t.Fatalf("mid-ramp drop rate = %v, want ~%v (±%v); minT=%v maxT=%v avg=%v",
			rate, wantP, tolerance, w.minT, w.maxT, w.GetAvgLen())
	}
}

func TestIsDrop_ForcedWhenMaxDPOneAndAboveMaxT(t *testing.T) {
	t.Parallel()

	w, err := NewWRED(100, 0, 1.0, 0.5)
	if err != nil {
		t.Fatalf("NewWRED: %v", err)
	}
	w.Update(50)

	for range 100 {
		if !w.IsDrop() {
			t.Fatal("expected IsDrop always true when avg>=maxT and maxDP=1")
		}
	}
}
