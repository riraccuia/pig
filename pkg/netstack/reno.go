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

import "math"

const (
	maxCwnd            = 1 << 30
	dupAckThreshold    = 3
	minSsthreshSegment = 2
)

// newReno implements RFC 5681 congestion control with the NewReno fast
// recovery modification of RFC 6582. All quantities are in bytes.
type newReno struct {
	mss        uint32
	cwnd       uint32
	ssthresh   uint32
	recover    uint32
	bytesAcked uint32
	dupAcks    int
	inRecovery bool
}

func (r *newReno) init(mss, iss uint32) {
	*r = newReno{
		mss:      mss,
		cwnd:     initialWindow(mss),
		ssthresh: math.MaxUint32,
		recover:  iss,
	}
}

// initialWindow follows RFC 5681 §3.1.
func initialWindow(mss uint32) uint32 {
	if mss > 2190 {
		return 2 * mss
	}
	if mss > 1095 {
		return 3 * mss
	}
	return 4 * mss
}

// onNewAck handles an ACK that advances SND.UNA and reports whether the
// first unacknowledged segment must be retransmitted (an RFC 6582 partial ACK).
func (r *newReno) onNewAck(acked, ack, flight uint32) bool {
	r.dupAcks = 0
	if r.inRecovery {
		return r.onRecoveryAck(acked, ack, flight)
	}
	r.grow(acked)
	return false
}

// onRecoveryAck implements RFC 6582 §3.2 steps 3 and 5.
func (r *newReno) onRecoveryAck(acked, ack, flight uint32) bool {
	if seqGT(ack, r.recover) {
		r.inRecovery = false
		r.bytesAcked = 0
		r.cwnd = min(r.ssthresh, max(flight, r.mss)+r.mss)
		return false
	}
	r.cwnd -= min(acked, r.cwnd)
	if acked >= r.mss {
		r.cwnd += r.mss
	}
	r.cwnd = max(r.cwnd, r.mss)
	return true
}

// grow applies slow start or congestion avoidance (RFC 5681 §3.1).
func (r *newReno) grow(acked uint32) {
	if r.cwnd < r.ssthresh {
		r.cwnd = min(r.cwnd+min(acked, r.mss), maxCwnd)
		return
	}
	r.bytesAcked += acked
	if r.bytesAcked < r.cwnd {
		return
	}
	r.bytesAcked -= r.cwnd
	r.cwnd = min(r.cwnd+r.mss, maxCwnd)
}

// onDupAck counts duplicate ACKs and reports whether to fast retransmit
// (RFC 6582 §3.2 steps 2 and 4).
func (r *newReno) onDupAck(sndUna, sndMax, flight uint32) bool {
	if r.inRecovery {
		r.cwnd = min(r.cwnd+r.mss, maxCwnd)
		return false
	}
	r.dupAcks++
	if r.dupAcks != dupAckThreshold || !seqGT(sndUna, r.recover) {
		return false
	}
	r.ssthresh = max(flight/2, minSsthreshSegment*r.mss)
	r.recover = sndMax - 1
	r.cwnd = r.ssthresh + dupAckThreshold*r.mss
	r.inRecovery = true
	return true
}

// onRTO collapses the window to one segment (RFC 5681 §3.1, RFC 6582 §3.2 step 6).
func (r *newReno) onRTO(flight, sndMax uint32) {
	r.ssthresh = max(flight/2, minSsthreshSegment*r.mss)
	r.cwnd = r.mss
	r.recover = sndMax - 1
	r.inRecovery = false
	r.dupAcks = 0
	r.bytesAcked = 0
}
