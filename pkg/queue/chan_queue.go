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

// Package queue provides queue implementations for packet buffering and management.
package queue

import (
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/queue/drand"
	"github.com/riraccuia/pig/pkg/queue/wred"
)

// ChanQueue implements a channel-based queue with WRED support for IPv4 packets.
// It provides congestion control through WRED and probabilistic packet dropping.
type ChanQueue struct {
	wred      *wred.WRED            // WRED instance for congestion management
	threshold int                   // Queue length threshold for drop decisions
	ct        *drand.CondensedTable // Probability table for drop decisions
	size      int                   // Queue size
	C         chan network.IPPacket // Channel for packet buffering
}

// NewChanQueue creates a new channel-based queue with the specified length.
//
// Parameters:
//   - len: The buffer size of the underlying channel
//
// Returns:
//   - *ChanQueue: A new queue instance
func NewChanQueue(size int) *ChanQueue {
	return &ChanQueue{
		C:    make(chan network.IPPacket, size),
		size: size,
	}
}

// WithWRED configures WRED support for the queue with specified parameters.
//
// Parameters:
//   - wred: WRED instance for queue length averaging
//   - dropProbability: Probability of dropping a packet when threshold is exceeded
//   - threshold: Queue length threshold as a fraction of total capacity
//
// Returns:
//   - *ChanQueue: The queue instance with WRED configured
func (q *ChanQueue) WithWRED(wred *wred.WRED, dropProbability, threshold float64) *ChanQueue {
	q.wred = wred
	q.threshold = int(threshold * float64(q.size))
	// 0: drop, 1: pass
	q.ct = drand.NewCondensedTable([]any{0, 1}, []float64{dropProbability, 1 - dropProbability})
	return q
}

// Len returns the current length of the queue.
// If WRED is enabled, it returns the exponentially weighted moving average length.
//
// Returns:
//   - int: Current queue length or WRED average length
func (q *ChanQueue) Len() int {
	if q.wred != nil {
		q.wred.Update(float64(len(q.C)))
		return int(q.wred.GetAvgLen())
	}
	return len(q.C)
}

// IsDrop determines whether an incoming packet should be dropped
// based on the current queue length and configured drop probability.
//
// Returns:
//   - bool: true if the packet should be dropped, false otherwise
func (q *ChanQueue) IsDrop() bool {
	if q.ct == nil {
		return false
	}
	if q.Len() > q.threshold {
		return q.ct.Sample() == 0
	}
	return false
}
