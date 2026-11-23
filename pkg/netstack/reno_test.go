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

import "testing"

func TestLimitedTransmit(t *testing.T) {
	const mss = 1000
	var r newReno
	r.init(mss, 0)
	r.cwnd = 10 * mss
	sndUna, sndMax := uint32(1), uint32(1+10*mss)
	flight := uint32(10 * mss)

	for dup := 1; dup < dupAckThreshold; dup++ {
		if r.onDupAck(sndUna, sndMax, flight) {
			t.Fatalf("fast retransmit on duplicate ACK %d", dup)
		}
		if got, want := r.sendWindow(), r.cwnd+uint32(dup)*mss; got != want {
			t.Fatalf("send window after duplicate ACK %d = %d, want %d", dup, got, want)
		}
		r.onTransmit(flight, mss)
		flight += mss
		sndMax += mss
	}
	if r.cwnd != 10*mss {
		t.Fatalf("Limited Transmit changed cwnd to %d", r.cwnd)
	}

	if !r.onDupAck(sndUna, sndMax, flight) {
		t.Fatal("no fast retransmit on the third duplicate ACK")
	}
	if want := uint32(10 * mss / 2); r.ssthresh != want {
		t.Fatalf("ssthresh = %d, want %d excluding Limited Transmit data", r.ssthresh, want)
	}
	if r.sendWindow() != r.cwnd {
		t.Fatalf("send window %d differs from cwnd %d during recovery", r.sendWindow(), r.cwnd)
	}
}

func TestRepeatedTimeoutKeepsSsthresh(t *testing.T) {
	const mss = 1000
	var r newReno
	r.init(mss, 0)
	sndMax := uint32(1 + 40*mss)
	r.onRTO(40*mss, sndMax)
	if r.ssthresh != 20*mss {
		t.Fatalf("ssthresh after the first timeout = %d, want %d", r.ssthresh, 20*mss)
	}

	r.onNewAck(51, 52, mss)
	r.onRTO(mss, sndMax)
	if r.ssthresh != 20*mss {
		t.Fatalf("ssthresh after a timeout of retransmitted data = %d, want %d", r.ssthresh, 20*mss)
	}

	r.onNewAck(40*mss-51, sndMax, 0)
	r.onRTO(4*mss, sndMax+4*mss)
	if r.ssthresh != minSsthreshSegment*mss {
		t.Fatalf("ssthresh after a timeout of new data = %d, want %d", r.ssthresh, minSsthreshSegment*mss)
	}
}

func TestSlowStartGrowthPerAck(t *testing.T) {
	const mss = 1000
	cases := []struct {
		name  string
		acked uint32
		want  uint32
	}{
		{"grows by the bytes acknowledged", 3 * mss, 3 * mss},
		{"is bounded for ACKs covering many segments", 16 * mss, maxSlowStartSegments * mss},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r newReno
			r.init(mss, 0)
			start := r.cwnd
			r.grow(tc.acked)
			if got := r.cwnd - start; got != tc.want {
				t.Fatalf("cwnd grew by %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLimitedTransmitEndsOnNewAck(t *testing.T) {
	const mss = 1000
	var r newReno
	r.init(mss, 0)
	r.onDupAck(1, 1+4*mss, 4*mss)
	r.onTransmit(r.cwnd, mss)
	r.onNewAck(mss, 1+mss, 4*mss)
	if r.sendWindow() != r.cwnd || r.limitedSent != 0 {
		t.Fatalf("Limited Transmit still active after a new ACK: window %d, cwnd %d, limited %d", r.sendWindow(), r.cwnd, r.limitedSent)
	}
}
