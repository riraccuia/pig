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

package wireguard

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// idleWatchThreshold is how long peer rx_bytes may stay unchanged before
	// the listen-side watcher closes the conn. Matches OpenWrt's wireguard
	// watchdog and WireGuard REJECT_AFTER_TIME (180s).
	idleWatchThreshold = 180 * time.Second

	idlePollMin = time.Second
	idlePollMax = 10 * time.Second
)

// idleState tracks peer liveness via wireguard-go rx_bytes (keepalives count).
type idleState struct {
	peerKeyHex string
	pollPeriod time.Duration
	threshold  time.Duration
	stop       chan struct{}
	stopped    atomic.Bool
}

func idlePollPeriod(threshold time.Duration) time.Duration {
	p := threshold / 3
	p = max(p, idlePollMin)
	p = min(p, idlePollMax)
	return p
}

// startIdleWatcher starts the rx_bytes poller for listen/accept conns.
// peerKeyHex is the hex public key of the peer whose rx_bytes to watch.
func (c *Conn) startIdleWatcher(peerKeyHex string) {
	c.startIdleWatcherWithThreshold(peerKeyHex, idleWatchThreshold)
}

// startIdleWatcherWithThreshold is used by tests with a short threshold.
func (c *Conn) startIdleWatcherWithThreshold(peerKeyHex string, threshold time.Duration) {
	if c == nil || peerKeyHex == "" || threshold <= 0 {
		return
	}
	if c.idle != nil {
		return
	}
	c.idle = &idleState{
		peerKeyHex: peerKeyHex,
		pollPeriod: idlePollPeriod(threshold),
		threshold:  threshold,
		stop:       make(chan struct{}),
	}
	go c.idleLoop()
}

func (c *Conn) stopIdleWatcher() {
	if c == nil || c.idle == nil {
		return
	}
	if c.idle.stopped.CompareAndSwap(false, true) {
		close(c.idle.stop)
	}
}

func (c *Conn) idleLoop() {
	s := c.idle
	ticker := time.NewTicker(s.pollPeriod)
	defer ticker.Stop()

	var (
		lastRX     uint64
		lastChange time.Time
		seenLive   bool
	)

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}

		if c.dev == nil {
			continue
		}
		ipc, err := c.dev.IpcGet()
		if err != nil {
			continue
		}
		rx, ok := peerRxBytes(ipc, s.peerKeyHex)
		if !ok {
			continue
		}

		now := time.Now()
		if !seenLive {
			if rx == 0 {
				continue
			}
			// First authenticated RX observed; start the silence clock.
			seenLive = true
			lastRX = rx
			lastChange = now
			continue
		}

		if rx != lastRX {
			lastRX = rx
			lastChange = now
			continue
		}

		if now.Sub(lastChange) >= s.threshold {
			_ = c.Close()
			return
		}
	}
}

// peerRxBytes returns rx_bytes for the peer with the given hex public key.
func peerRxBytes(ipc, peerKeyHex string) (uint64, bool) {
	current := ""
	for line := range strings.SplitSeq(ipc, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			current = val
		case "rx_bytes":
			if current != peerKeyHex {
				continue
			}
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}
