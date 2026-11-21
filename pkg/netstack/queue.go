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

import (
	"io"
	"os"
	"sync"
	"time"
)

// roomWaiter is notified once a full packetQueue has drained.
type roomWaiter interface {
	onQueueRoom()
}

// packetQueue holds outbound datagrams until Stack.Read collects them.
// push never blocks, so segment processing cannot deadlock against a reader
// that is itself feeding datagrams back into the stack.
//
// Bulk data is held back at highWater rather than dropped at limit, because
// TCP would treat a local drop as congestion. The headroom above highWater
// keeps ACKs and retransmissions flowing while senders wait.
type packetQueue struct {
	mu           sync.Mutex
	cond         *sync.Cond
	pkts         [][]byte
	limit        int
	highWater    int
	lowWater     int
	waiters      map[roomWaiter]struct{}
	closed       bool
	readDeadline deadline
}

func newPacketQueue(limit int) *packetQueue {
	highWater := max(limit-limit/4, 1)
	q := &packetQueue{
		limit:     limit,
		highWater: highWater,
		lowWater:  highWater / 2,
		waiters:   make(map[roomWaiter]struct{}),
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *packetQueue) setReadDeadline(t time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.readDeadline.set(q.cond, t)
	return nil
}

// push takes ownership of pkt, a buffer from allocateMem: it is either queued
// or released. It reports false when pkt was dropped.
func (q *packetQueue) push(pkt []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.pkts) >= q.limit {
		releaseMem(pkt)
		return false
	}
	q.pkts = append(q.pkts, pkt)
	q.cond.Signal()
	return true
}

// acceptsBulk reports whether bulk data may be queued. When it may not, w is
// notified once the queue drains to lowWater.
func (q *packetQueue) acceptsBulk(w roomWaiter) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.pkts) < q.highWater {
		return true
	}
	q.waiters[w] = struct{}{}
	return false
}

// pop blocks until a datagram is available and copies it into dst. A buffer
// too small for the next datagram leaves it queued. Waiters are notified
// after the queue lock is released, because they take their own locks and
// push again.
func (q *packetQueue) pop(dst []byte) (int, error) {
	n, ready, err := q.take(dst)
	for w := range ready {
		w.onQueueRoom()
	}
	return n, err
}

func (q *packetQueue) take(dst []byte) (int, map[roomWaiter]struct{}, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.pkts) == 0 {
		if q.closed {
			return 0, nil, io.EOF
		}
		if q.readDeadline.exceeded() {
			return 0, nil, os.ErrDeadlineExceeded
		}
		q.cond.Wait()
	}
	pkt := q.pkts[0]
	if len(dst) < len(pkt) {
		return 0, nil, io.ErrShortBuffer
	}
	q.pkts[0] = nil
	q.pkts = q.pkts[1:]
	n := copy(dst, pkt)
	releaseMem(pkt)
	return n, q.takeWaiters(), nil
}

// takeWaiters hands over the waiters once the queue has drained to lowWater.
func (q *packetQueue) takeWaiters() map[roomWaiter]struct{} {
	if len(q.waiters) == 0 || len(q.pkts) > q.lowWater {
		return nil
	}
	ready := q.waiters
	q.waiters = make(map[roomWaiter]struct{})
	return ready
}

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	for _, pkt := range q.pkts {
		releaseMem(pkt)
	}
	q.pkts = nil
	clear(q.waiters)
	q.readDeadline.stop()
	q.cond.Broadcast()
}
