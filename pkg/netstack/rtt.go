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

// rttEstimator computes the retransmission timeout as specified in RFC 6298.
type rttEstimator struct {
	srtt      time.Duration
	rttvar    time.Duration
	rto       time.Duration
	minRTO    time.Duration
	hasSample bool
}

func newRTTEstimator(minRTO time.Duration) rttEstimator {
	e := rttEstimator{minRTO: minRTO}
	e.rto = e.clamp(initialRTO)
	return e
}

// sample applies RFC 6298 §2.2 and §2.3 with alpha = 1/8 and beta = 1/4.
func (e *rttEstimator) sample(r time.Duration) {
	if !e.hasSample {
		e.srtt = r
		e.rttvar = r / 2
		e.hasSample = true
		e.update()
		return
	}
	diff := e.srtt - r
	if diff < 0 {
		diff = -diff
	}
	e.rttvar = (3*e.rttvar + diff) / 4
	e.srtt = (7*e.srtt + r) / 8
	e.update()
}

// backoff doubles the timeout after an expiry (RFC 6298 §5.5).
func (e *rttEstimator) backoff() {
	e.rto = e.clamp(2 * e.rto)
}

func (e *rttEstimator) update() {
	e.rto = e.clamp(e.srtt + max(clockGranularity, 4*e.rttvar))
}

func (e *rttEstimator) clamp(d time.Duration) time.Duration {
	return min(max(d, e.minRTO), maxRTO)
}

// rttTiming tracks the single segment being timed. Karn's algorithm requires
// that retransmitted segments are never sampled (RFC 6298 §3).
type rttTiming struct {
	active bool
	seq    uint32
	start  time.Time
}

func (c *Conn) startTiming(seq uint32) {
	if c.timing.active {
		return
	}
	c.timing = rttTiming{active: true, seq: seq, start: time.Now()}
}

func (c *Conn) sampleRTT(ack uint32) {
	if !c.timing.active || !seqGT(ack, c.timing.seq) {
		return
	}
	c.rtt.sample(time.Since(c.timing.start))
	c.timing.active = false
}
