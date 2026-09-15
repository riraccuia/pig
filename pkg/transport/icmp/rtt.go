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

package icmp

import (
	"math"
	"time"
)

const (
	alpha  = float64(0.125)
	beta   = float64(0.25)
	K      = 1
	minRTO = time.Millisecond * 300
	maxRTO = time.Second
)

type measurement struct {
	sendTime time.Time
	seq      uint32
}

// GetRTT returns the current RTT estimate.
func (c *Conn) GetRTT() time.Duration {
	srtt := time.Duration(c.rtt.Load())
	rttvar := time.Duration(c.rttvar.Load())

	// RTO = SRTT + 4×RTTVAR
	rto := srtt + K*rttvar

	// Enforce minimum RTO
	if rto < minRTO {
		rto = minRTO
	}

	if rto > maxRTO {
		rto = maxRTO
	}

	return rto
}

// updateRTT updates the RTT estimate using exponential moving average.
func (c *Conn) UpdateRTT(peerAck uint32) {
	val := c.rtoSeq.Load()
	if val == nil {
		return
	}
	m := val.(*measurement)
	if *m == (measurement{}) {
		return
	}
	c.rtoSeq.CompareAndSwap(m, &measurement{})

	if isUint32SeqHigher(m.seq, peerAck) {
		return
	}

	sample := time.Since(m.sendTime)
	currentRTT := time.Duration(c.rtt.Load())
	currentRTTVAR := time.Duration(c.rttvar.Load())

	// If this is the first measurement
	if currentRTT == 0 {
		srtt := sample
		rttvar := sample / 2
		c.rtt.Store(int64(srtt))
		c.rttvar.Store(int64(rttvar))
		return
	}

	// Calculate RTTVAR first using the current SRTT
	rttvar := time.Duration(float64(currentRTTVAR)*(1-beta) +
		math.Abs(float64(currentRTT-sample))*beta)

	// Then update SRTT
	srtt := time.Duration(float64(currentRTT)*(1-alpha) +
		float64(sample)*alpha)

	// Store the updated values
	c.rtt.Store(int64(srtt))
	c.rttvar.Store(int64(rttvar))
}

// BackoffRTO doubles the current RTO value as specified in RFC 6298.
// Returns the new RTO value.
func (c *Conn) BackoffRTO() time.Duration {
	currentRTO := c.GetRTT() // GetRTT actually returns RTO

	// Double the RTO (exponential backoff)
	newRTO := currentRTO * 2

	// RFC 6298 section 5.5 states there is no maximum value specified for RTO
	// However, we might want to add one in practice if needed

	return newRTO
}
