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
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN bridges pig's Conn and wireguard-go's tun.Device.
//
// Both directions are synchronous borrows: the producer does not return until
// the consumer has finished copying out of the lent buffer.
//
//	Conn.Write  → outbound / outAck ← Device.Read   (plaintext → encrypt)
//	Device.Write → inbound / inAck  ← Conn.Read     (decrypt → pig)
type fakeTUN struct {
	mtu       int
	name      string
	outbound  chan []byte
	outAck    chan struct{}
	inbound   chan []byte
	inAck     chan struct{}
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeTUN(name string, mtu int) *fakeTUN {
	if mtu <= 0 {
		mtu = 1420
	}
	t := &fakeTUN{
		mtu:      mtu,
		name:     name,
		outbound: make(chan []byte),
		outAck:   make(chan struct{}),
		inbound:  make(chan []byte),
		inAck:    make(chan struct{}),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
	//t.events <- tun.EventUp
	return t
}

func (t *fakeTUN) File() *os.File { return nil }

func (t *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case t.outAck <- struct{}{}:
			return 1, nil
		}
	}
}

func (t *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	if offset == -1 {
		t.closeOnce.Do(func() {
			close(t.closed)
			close(t.events)
		})
		return 0, io.EOF
	}
	for i, data := range bufs {
		if offset > len(data) {
			return i, io.ErrShortBuffer
		}
		select {
		case <-t.closed:
			return i, os.ErrClosed
		case t.inbound <- data[offset:]:
		}
		select {
		case <-t.closed:
			return i, os.ErrClosed
		case <-t.inAck:
		}
	}
	return len(bufs), nil
}

func (t *fakeTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *fakeTUN) Name() (string, error)    { return t.name, nil }
func (t *fakeTUN) Events() <-chan tun.Event { return t.events }
func (t *fakeTUN) BatchSize() int           { return 16 }

func (t *fakeTUN) Close() error {
	t.Write(nil, -1)
	return nil
}
