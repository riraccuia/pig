package drand

import (
	"math/rand"
	"sort"
)

// CondensedTable holds cumulative probabilities for fast sampling
type CondensedTable struct {
	outcomes []string
	cdf      []float64 // Cumulative distribution function values
}

// NewCondensedTable initializes the lookup table
func NewCondensedTable(outcomes []string, probabilities []float64) *CondensedTable {
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

// Sample draws an outcome using a precomputed CDF table
func (ct *CondensedTable) Sample() string {
	r := rand.Float64()                     // Generate random number in [0,1)
	index := sort.SearchFloat64s(ct.cdf, r) // Find the first index where r ≤ cdf[index]
	return ct.outcomes[index]
}
