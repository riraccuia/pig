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

package netstack

import "time"

const (
	minAckStretch = 2 // RFC 5681 §4.2: an ACK for at least every second full-sized segment
	maxAckStretch = 8
	// A burst has ended once no data arrived for ackPauseFactor times the
	// usual interval between segments.
	ackPauseFactor = 4
	minAckFlush    = time.Millisecond
)

// ackStretch adapts how many full-sized segments one ACK may cover. A steady
// flow ramps from minAckStretch to maxAckStretch, one segment per ACK sent at
// the threshold; anything that suggests the sender is recovering or short of
// window snaps it back to minAckStretch.
type ackStretch struct {
	segments int
	// gap is the smoothed interval between in-order data segments; last is
	// when the most recent one arrived, and oldest when the oldest
	// unacknowledged one did.
	gap    time.Duration
	last   time.Time
	oldest time.Time
}

func newAckStretch() ackStretch {
	return ackStretch{segments: minAckStretch}
}

func (a *ackStretch) reset() { a.segments = minAckStretch }

func (a *ackStretch) grow() { a.segments = min(a.segments+1, maxAckStretch) }

func (a *ackStretch) stretched() bool { return a.segments > minAckStretch }

// onArrival samples the interval since the previous in-order data segment
// with a gain of 1/8. Intervals of a delayed-ACK timeout or more are idle
// periods rather than spacing within a burst, so they are not sampled.
func (a *ackStretch) onArrival(now time.Time) {
	last := a.last
	a.last = now
	if last.IsZero() {
		return
	}
	sample := now.Sub(last)
	if sample >= delayedAckTimeout {
		return
	}
	if a.gap == 0 {
		a.gap = sample
		return
	}
	a.gap += (sample - a.gap) / 8
}

// ackDelay is how long an ACK may wait: the delayed-ACK timeout at the
// minimum stretch, or long enough for the rest of a burst when stretched.
func (a *ackStretch) ackDelay() time.Duration {
	if !a.stretched() {
		return delayedAckTimeout
	}
	return min(max(ackPauseFactor*a.gap, minAckFlush), delayedAckTimeout)
}

// ackWait is how much longer, at now, the pending ACK may wait: until the
// burst pauses, but never past the delayed-ACK timeout of the oldest
// unacknowledged segment.
func (a *ackStretch) ackWait(now time.Time) time.Duration {
	untilPause := a.ackDelay() - now.Sub(a.last)
	untilTimeout := delayedAckTimeout - now.Sub(a.oldest)
	return min(untilPause, untilTimeout)
}
