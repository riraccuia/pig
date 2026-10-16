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
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pion/transport/v5/udp"
	"github.com/riraccuia/pig/pkg/transport/wireguard/conn"
)

const (
	// WireGuard message type 1 = handshake initiation (little-endian u32).
	wgMessageInitiationType = 1
)

// Listener accepts WireGuard peers over a shared UDP socket (pion transport demux).
// Each Accept builds a Conn with DemuxBind for that remote.
type Listener struct {
	ctx  context.Context
	ln   net.Listener
	opts *setupOpts
}

func newSharedListener(ctx context.Context, opts *setupOpts) (*Listener, error) {
	lc := udp.ListenConfig{
		AcceptFilter: func(b []byte) bool {
			if len(b) < 4 {
				return false
			}
			return binary.LittleEndian.Uint32(b[:4]) == wgMessageInitiationType
		},
	}
	ln, err := lc.Listen(opts.networkStr, opts.localAddr)
	if err != nil {
		return nil, fmt.Errorf("wireguard listen: %w", err)
	}
	return &Listener{
		ctx:  ctx,
		ln:   ln,
		opts: opts,
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	c, err := l.acceptPeer(l.ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func (l *Listener) acceptPeer(ctx context.Context, raw net.Conn) (*Conn, error) {
	remote := raw.RemoteAddr()
	if remote == nil {
		return nil, fmt.Errorf("wireguard accept: missing remote addr")
	}

	opts := *l.opts
	opts.endpoint = remote.String()
	opts.remoteAddr = remote.(*net.UDPAddr)
	opts.localAddr = raw.LocalAddr().(*net.UDPAddr)
	if ua, ok := raw.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		opts.listenPort = ua.Port
	}

	bind := conn.NewSimpleBind(raw)

	wgConn, err := newConnWithBindWaitHandshake(ctx, &opts, bind)
	if err != nil {
		return nil, err
	}
	wgConn.underlyingConn = raw

	return wgConn, nil
}

func (l *Listener) Close() error {
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}
