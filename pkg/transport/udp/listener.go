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

package udp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/transport"
)

// listener implements the transport.Listener interface.
type listener struct {
	conn       net.PacketConn
	addr       net.Addr
	connChan   chan transport.Conn
	addrConns  map[string]*connection
	mu         sync.RWMutex
	readBuffer []byte
	ctx        context.Context
	cancel     context.CancelFunc
	logger     common.Logger
}

func newListener(logger common.Logger, conn net.PacketConn, addr net.Addr) *listener {
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{
		conn:       conn,
		addr:       addr,
		connChan:   make(chan transport.Conn),
		addrConns:  make(map[string]*connection),
		readBuffer: make([]byte, defaultBufferSize),
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
	}
	go l.readPackets()
	return l
}

func (l *listener) readPackets() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			n, raddr, err := l.conn.ReadFrom(l.readBuffer)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					l.logger.Errorf("UDP server read error: %v", err)
				}
				return
			}

			raddrStr := raddr.String()
			l.mu.RLock()
			conn, exists := l.addrConns[raddrStr]
			l.mu.RUnlock()

			if !exists {
				// New connection
				conn = &connection{
					conn:     l.conn,
					raddr:    raddr,
					readChan: make(chan []byte, 256),
					ctx:      l.ctx,
				}
				l.mu.Lock()
				l.addrConns[raddrStr] = conn
				l.mu.Unlock()
				l.connChan <- conn
			}

			// Copy the data to avoid race conditions
			data := make([]byte, n)
			copy(data, l.readBuffer[:n])
			select {
			case conn.readChan <- data:
			default:
				// Drop packet if buffer is full
				l.logger.Errorf("UDP server data channel full, dropping packet from %s", raddrStr)
			}
		}
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, fmt.Errorf("listener closed")
	case conn := <-l.connChan:
		return conn, nil
	}
}

func (l *listener) Close() error {
	l.cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, conn := range l.addrConns {
		close(conn.readChan)
	}
	l.addrConns = nil
	return l.conn.Close()
}

func (l *listener) Addr() net.Addr {
	return l.addr
}
