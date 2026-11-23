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

type countingWaiter struct {
	notified int
}

func (w *countingWaiter) onQueueRoom() { w.notified++ }

func TestPacketQueueHoldsBulkDataAtHighWater(t *testing.T) {
	q := newPacketQueue(8)
	w := &countingWaiter{}
	for range q.highWater {
		if !q.acceptsBulk(w) {
			t.Fatalf("bulk data refused below high water (%d queued)", len(q.pkts))
		}
		q.push(make([]byte, 1))
	}
	if q.acceptsBulk(w) {
		t.Fatalf("bulk data accepted at high water %d", q.highWater)
	}
	if !q.push(make([]byte, 1)) {
		t.Fatal("control datagram dropped in the headroom above high water")
	}

	buf := make([]byte, 1)
	for len(q.pkts) > q.lowWater {
		if w.notified != 0 {
			t.Fatalf("waiter notified with %d datagrams queued, above low water %d", len(q.pkts), q.lowWater)
		}
		if _, err := q.pop(buf); err != nil {
			t.Fatalf("pop: %v", err)
		}
	}
	if w.notified != 1 {
		t.Fatalf("waiter notified %d times at low water, want 1", w.notified)
	}
	if _, err := q.pop(buf); err != nil {
		t.Fatalf("pop: %v", err)
	}
	if w.notified != 1 {
		t.Fatalf("waiter notified again without re-registering: %d", w.notified)
	}
	if !q.acceptsBulk(w) {
		t.Fatal("bulk data refused after draining")
	}
}
