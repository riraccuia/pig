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

package drand

import (
	"math/rand"
	"sort"
)

// CondensedTable holds cumulative probabilities for fast sampling.
type CondensedTable struct {
	outcomes []any
	cdf      []float64 // Cumulative distribution function values
}

// NewCondensedTable initializes the lookup table.
func NewCondensedTable(outcomes []any, probabilities []float64) *CondensedTable {
	n := len(outcomes)
	cdf := make([]float64, n)

	// Compute cumulative probabilities
	cdf[0] = probabilities[0]
	for i := 1; i < n; i++ {
		cdf[i] = cdf[i-1] + probabilities[i]
	}

	// Ensure last value is exactly 1.0 to avoid precision errors
	cdf[n-1] = 1.0

	return &CondensedTable{outcomes: outcomes, cdf: cdf}
}

// Sample draws an outcome using a precomputed CDF table.
func (ct *CondensedTable) Sample() any {
	r := rand.Float64()                     // Generate random number in [0,1)
	index := sort.SearchFloat64s(ct.cdf, r) // Find the first index where r ≤ cdf[index]
	return ct.outcomes[index]
}
