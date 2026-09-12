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

package demux

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/network"
)

var ErrAdapterClosed = errors.New("adapter closed")

// Adapter implements common.TunnelAdapter as a per-tunnel view of the
// shared TUN device. Reads block on an inbox channel fed by the demux;
// writes delegate directly to the real adapter.
type Adapter struct {
	parent    *Demux
	outqueue  common.PacketQueue
	inqueue   common.PacketQueue
	done      <-chan struct{}
	closeOnce sync.Once
	cancel    context.CancelFunc
}

func (d *Demux) NewAdapter(ctx context.Context, queueSize int) *Adapter {
	if queueSize <= 0 {
		queueSize = config.DefaultQueueSize
	}
	demuxCtx, cancel := context.WithCancel(ctx)
	a := &Adapter{
		parent:   d,
		outqueue: make(common.PacketQueue, queueSize),
		inqueue:  d.inbound,
		done:     demuxCtx.Done(),
		cancel:   cancel,
	}
	return a
}

func (a *Adapter) OutQueue() (common.PacketQueue, error) {
	select {
	case <-a.done:
		return nil, ErrAdapterClosed
	default:
		return a.outqueue, nil
	}
}

func (a *Adapter) InQueue() (common.PacketQueue, error) {
	select {
	case <-a.done:
		return nil, ErrAdapterClosed
	default:
		return a.inqueue, nil
	}
}

func (a *Adapter) Read(b []byte) (int, error) {
	select {
	case pkt, ok := <-a.outqueue:
		if !ok {
			return 0, ErrAdapterClosed
		}
		n := copy(b, pkt.Bytes()[:pkt.TotalLength()])
		a.parent.bufferPool.PutBuffer(pkt.Bytes())
		return n, nil
	case <-a.done:
		return 0, ErrAdapterClosed
	}
}

func (a *Adapter) Write(b []byte) (int, error) {
	select {
	case <-a.done:
		return 0, ErrAdapterClosed
	default:
	}
	pkt := network.IPv4Packet(a.parent.bufferPool.GetBuffer(a.parent.mtu))
	copy(pkt[:], b)
	select {
	case a.inqueue <- pkt:
		return len(b), nil
	case <-a.done:
		a.parent.bufferPool.PutBuffer(pkt)
		return 0, ErrAdapterClosed
	default:
		a.parent.bufferPool.PutBuffer(pkt)
		return 0, errors.New("demux outbound channel full, dropping packet")
	}
}

func (a *Adapter) Close() error {
	a.cancel()
	return nil
}
func (a *Adapter) IP() net.IP         { return a.parent.adapter.IP() }
func (a *Adapter) IP6() net.IP        { return a.parent.adapter.IP6() }
func (a *Adapter) IPNet() *net.IPNet  { return a.parent.adapter.IPNet() }
func (a *Adapter) IPNet6() *net.IPNet { return a.parent.adapter.IPNet6() }
func (a *Adapter) Name() string       { return a.parent.adapter.Name() }
func (a *Adapter) Index() int         { return a.parent.adapter.Index() }
