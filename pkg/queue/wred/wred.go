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
)

// WRED represents a Weighted Random Early Detection queue manager.
// It maintains an exponentially weighted moving average of the queue length
// to make decisions about packet drops.
type WRED struct {
	// avgQueueLen stores the exponentially weighted moving average queue length.
	avgQueueLen float64

	// factor is the weight factor used in the WRED calculation.
	factor float64

	// w is the derived weight used in the exponential moving average calculation.
	// w = 2^(-weight)
	w float64
}

// NewWRED creates and initializes a new WRED instance with the specified weight.
// The weight parameter determines how much influence recent samples have on the average.
// Larger values of weight result in less influence from new samples.
//
// Parameters:
//   - weight: The weight factor for the average calculation
//
// Returns:
//   - *WRED: A new WRED instance
//   - error: An error if the weight is less than 0
func NewWRED(weight float64) (*WRED, error) {
	if weight < 0 {
		return nil, fmt.Errorf("weight must be greater than 0")
	}
	return &WRED{
		factor: weight,
		w:      math.Pow(2, -weight),
	}, nil
}

// Update updates the average queue length using the exponential weighted moving average formula:
// avg = current * (1-w) + old_avg * w
//
// Parameters:
//   - queueLen: The current queue length
func (w *WRED) Update(queueLen float64) {
	w.avgQueueLen = queueLen*(1-w.w) + w.avgQueueLen*w.w
}

// GetAvgLen returns the current exponentially weighted moving average queue length.
//
// Returns:
//   - float64: The current average queue length
func (w *WRED) GetAvgLen() float64 {
	return w.avgQueueLen
}
