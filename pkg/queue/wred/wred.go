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

// Package wred implements Weighted Random Early Detection queue management algorithm.
package wred

import (
	"fmt"
	"math"
	"math/rand/v2"
)

// WRED represents a Weighted Random Early Detection queue manager.
// It maintains an exponentially weighted moving average of the queue length
// to make decisions about packet drops.
type WRED struct {
	// avgQueueLen stores the exponentially weighted moving average queue length.
	avgQueueLen float64

	// factor is the weight factor used in the WRED calculation.
	factor float64

	// maxDP is the maximum drop probability
	maxDP float64

	// minT is the minimum threshold
	minT float64

	// maxT is the maximum threshold
	maxT float64

	// w is the derived weight used in the exponential moving average calculation.
	// w = 2^(-weight)
	w float64
}

// NewWRED creates and initializes a new WRED instance with the specified weight.
// The weight parameter determines how much influence recent samples have on the average.
// Larger values of weight result in less influence from new samples.
//
// Parameters:
//   - weight: weight factor for the average calculation
//   - dropProbability: drop probability
//   - threshold: threshold as a fraction of queue length
//
// Returns:
//   - *WRED: A new WRED instance
//   - error: An error if the weight is less than 0
func NewWRED(qlen int, weight, dropProbability, threshold float64) (*WRED, error) {
	if weight <= 0 {
		return nil, fmt.Errorf("weight must be greater than 0")
	}
	if dropProbability < 0 || dropProbability > 1 {
		return nil, fmt.Errorf("drop probability must be between 0 and 1")
	}
	if threshold < 0 || threshold > 1 {
		return nil, fmt.Errorf("threshold must be between 0 and 1")
	}
	if qlen <= 0 {
		return nil, fmt.Errorf("wred's queue length must be > 0")
	}
	maxT := threshold * float64(qlen)
	minT := math.Round(maxT*0.5*100) / 100
	if minT >= maxT {
		minT = maxT // threshold==0 edge
	}
	return &WRED{
		factor: weight,
		maxDP:  dropProbability,
		minT:   minT,
		maxT:   maxT,
		w:      math.Pow(2, -weight),
	}, nil
}

// Update updates the average queue length using the exponential weighted moving average formula:
// avg = (1-w)*avg + w*queueLen
// where w = 2^(-weight) is small, so the average moves slowly.
func (w *WRED) Update(queueLen float64) {
	w.avgQueueLen = (1-w.w)*w.avgQueueLen + w.w*queueLen
}

// GetAvgLen returns the current exponentially weighted moving average queue length.
//
// Returns:
//   - float64: The current average queue length
func (w *WRED) GetAvgLen() float64 {
	return w.avgQueueLen
}

// IsDrop returns true if the next packet should be dropped based on the current queue length and configured drop probability.
//
// Returns:
//   - bool: true if the next packet should be dropped, false otherwise
func (w *WRED) IsDrop() bool {
	if w.maxDP == 0 {
		return false
	}
	avg := w.avgQueueLen
	if avg < w.minT {
		return false
	}
	if avg >= w.maxT {
		return rand.Float64() < w.maxDP
	}
	p := w.maxDP * (avg - w.minT) / (w.maxT - w.minT)
	return rand.Float64() < p
}
