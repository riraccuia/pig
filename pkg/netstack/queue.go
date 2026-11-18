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

// packetQueue holds outbound datagrams until Stack.Read collects them.
// push never blocks, so segment processing cannot deadlock against a reader
// that is itself feeding datagrams back into the stack.
type packetQueue struct {
	mu           sync.Mutex
	cond         *sync.Cond
	pkts         [][]byte
	limit        int
	closed       bool
	readDeadline deadline
}

func newPacketQueue(limit int) *packetQueue {
	q := &packetQueue{limit: limit}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *packetQueue) setReadDeadline(t time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.readDeadline.set(q.cond, t)
	return nil
}

// push enqueues pkt and reports false when it was dropped.
func (q *packetQueue) push(pkt []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.pkts) >= q.limit {
		return false
	}
	q.pkts = append(q.pkts, pkt)
	q.cond.Signal()
	return true
}

// pop blocks until a datagram is available and copies it into dst. A buffer
// too small for the next datagram leaves it queued.
func (q *packetQueue) pop(dst []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.pkts) == 0 {
		if q.closed {
			return 0, io.EOF
		}
		if q.readDeadline.exceeded() {
			return 0, os.ErrDeadlineExceeded
		}
		q.cond.Wait()
	}
	pkt := q.pkts[0]
	if len(dst) < len(pkt) {
		return 0, io.ErrShortBuffer
	}
	q.pkts[0] = nil
	q.pkts = q.pkts[1:]
	return copy(dst, pkt), nil
}

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.pkts = nil
	q.readDeadline.stop()
	q.cond.Broadcast()
}
