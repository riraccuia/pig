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
	"sync"
	"time"
)

// connTimer runs fn with the connection mutex held. Every arm or stop bumps
// the generation, so a callback that raced with a stop becomes a no-op.
// All methods must be called with the connection mutex held.
type connTimer struct {
	timer  *time.Timer
	gen    uint64
	active bool
}

func (t *connTimer) arm(c *Conn, d time.Duration, fn func()) {
	t.stop()
	t.active = true
	gen := t.gen
	t.timer = time.AfterFunc(d, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if t.gen != gen || !t.active {
			return
		}
		t.active = false
		fn()
	})
}

func (t *connTimer) stop() {
	t.gen++
	t.active = false
	if t.timer != nil {
		t.timer.Stop()
	}
}

// deadline implements read and write deadlines by waking the waiters on cond.
// set must be called with cond.L held.
type deadline struct {
	at    time.Time
	timer *time.Timer
}

func (d *deadline) set(cond *sync.Cond, t time.Time) {
	d.stop()
	d.at = t
	cond.Broadcast()
	if t.IsZero() {
		return
	}
	d.timer = time.AfterFunc(time.Until(t), func() {
		// Holding cond.L keeps the broadcast from landing between a waiter's
		// exceeded() check and its Wait(), where it would be lost.
		cond.L.Lock()
		defer cond.L.Unlock()
		cond.Broadcast()
	})
}

func (d *deadline) stop() {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func (d *deadline) exceeded() bool {
	return !d.at.IsZero() && !time.Now().Before(d.at)
}
