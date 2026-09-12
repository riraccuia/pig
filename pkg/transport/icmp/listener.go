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

package icmp

import (
	"context"
	"fmt"
	"hash/maphash"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// sharedListener handles the raw ICMP socket and connection dispatching.
type sharedListener struct {
	isServer   bool
	ip4Conn    *ipv4.RawConn
	conn       *ipConn
	localAddr  *net.IPAddr
	ctx        context.Context
	cancel     context.CancelFunc
	mss        int
	clients    sync.Map // map[clientKey]*connection
	connChan   chan transport.Conn
	packetChan chan *Packet
	bufPool    sync.Pool
	logger     common.Logger
}

var h maphash.Hash

func getClientKey(ip net.IP, icmpID uint16) uint64 {
	defer h.Reset()
	// use internal golang hash function to get a unique key for the client connection
	h.Write(ip.To4())
	// get the underlying memory of the icmpID
	icmpIDBytes := (*[2]byte)(unsafe.Pointer(&icmpID))
	h.Write(icmpIDBytes[:])
	return h.Sum64()
}

func (l *sharedListener) getBuffer() []byte {
	return *l.bufPool.Get().(*[]byte)
}

func (l *sharedListener) clearMemory(m []byte) {
	l.bufPool.Put(&m)
}

// newSharedListener creates a new shared ICMP socket listener.
func newSharedListener(ctx context.Context, logger common.Logger, bindAddr *net.IPAddr, iface *net.Interface, isServer bool) (*sharedListener, error) {
	conn, err := newIcmpIPConn(bindAddr, iface, isServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket: %w", err)
	}

	ip4Conn, err := ipv4.NewRawConn(conn.IPConn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create raw connection: %w", err)
	}

	ip4Conn.SetWriteBuffer(defaultBufferSize)
	ip4Conn.SetReadBuffer(defaultBufferSize)

	listenerCtx, cancel := context.WithCancel(ctx)
	l := &sharedListener{
		isServer:   isServer,
		ip4Conn:    ip4Conn,
		conn:       conn,
		localAddr:  conn.LocalAddr().(*net.IPAddr),
		ctx:        listenerCtx,
		cancel:     cancel,
		mss:        iface.MTU - ipHeaderSize - icmpHeaderSize,
		connChan:   make(chan transport.Conn, 1024),
		packetChan: make(chan *Packet, 1024),
		bufPool:    sync.Pool{New: func() any { buffer := make([]byte, iface.MTU); return &buffer }},
		logger:     logger,
	}

	// Start the packet dispatch loop
	go l.dispatchPackets()
	runtime.Gosched()
	// Start the packet reading loop
	go l.readPackets()
	runtime.Gosched()

	return l, nil
}

// Accept implements the Listener interface.
func (l *sharedListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, fmt.Errorf("listener closed")
	case conn := <-l.connChan:
		return conn, nil
	}
}

// Close implements the Listener interface.
func (l *sharedListener) Close() error {
	l.cancel()
	l.clients.Range(func(key, value interface{}) bool {
		conn := value.(*Conn)
		conn.Close()
		l.clients.Delete(key)
		return true
	})
	return l.conn.Close()
}

// readPackets continuously reads ICMP packets and processes them for the listener.
func (l *sharedListener) readPackets() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			// buffer := make([]byte, l.mtu)
			buffer := l.getBuffer()

			n, _, _, ipSrc, err := l.conn.ReadMsgIP(buffer, nil)
			if err != nil {
				l.logger.Errorf("Error reading ICMP packet: %v", err)
				l.clearMemory(buffer)
				continue
			}

			packet, err := NewPacket(buffer, n)
			if err != nil {
				l.logger.Errorf("Error parsing ICMP packet: %v", err)
				l.clearMemory(buffer)
				continue
			}
			packet.IPSrc = ipSrc.IP.To4()

			select {
			case l.packetChan <- packet:
			default:
				l.clearMemory(buffer)
				l.logger.Errorf("packet channel full, dropping packet, %s", packet.IcmpPacket())
			}
		}
	}
}

// dispatchPackets handles dispatching ICMP packets to their respective connections.
func (l *sharedListener) dispatchPackets() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case packet := <-l.packetChan:
			//transport.Logger.Infof("dispatching packet, icmp type: %d, icmp id: %d, icmp seq: %d", ipv4.ICMPType(packet.payload[0]), binary.BigEndian.Uint16(packet.payload[4:6]), binary.BigEndian.Uint16(packet.payload[6:8]))

			if l.isServer && packet.IcmpType != ipv4.ICMPTypeEcho {
				l.logger.Errorf("received non-echo request, %s", packet.IcmpPacket())
				l.clearMemory(packet.buffer)
				continue
			}
			if !l.isServer && packet.IcmpType != ipv4.ICMPTypeEchoReply {
				l.logger.Errorf("received non-echo reply, %s", packet.IcmpPacket())
				l.clearMemory(packet.buffer)
				continue
			}

			var conn *Conn
			conn = l.getClientConn(packet.IPSrc, packet.IcmpEchoID, packet.IcmpCode)

			if conn == nil {
				l.logger.Errorf("failed to find packet connection, ip: %s, icmp id: %d", packet.IPSrc.String(), packet.IcmpEchoID)
				l.clearMemory(packet.buffer)
				continue
			}

			// Forward packet to the appropriate connection
			select {
			case conn.incoming <- packet:
				// transport.Logger.Infof("forwarded packet to connection, ip: %s, icmp id: %d, icmp seq: %d", packet.header.Src.String(), icmpID, binary.BigEndian.Uint16(packet.payload[6:8]))
			default:
				l.clearMemory(packet.buffer)
				l.logger.Errorf("Connection buffer full, dropping packet")
			}
		}
	}
}

func (l *sharedListener) getClientConn(ip net.IP, icmpID uint16, echoCode uint8) *Conn {
	key := getClientKey(ip, icmpID)
	_conn, exists := l.clients.Load(key)
	if exists {
		return _conn.(*Conn)
	}

	if echoCode == 255 {
		return nil
	}

	l.logger.Infof("New client connection (%d), ip: %s, icmp id: %d", key, ip.String(), icmpID)

	conn := newConnection(
		l.ctx,
		l,
		&net.IPAddr{IP: ip},
		icmpID,
	)

	l.clients.Store(key, conn)

	select {
	case l.connChan <- conn:
	default:
		conn.Close()
		l.clients.Delete(key)
		l.logger.Errorf("Accept channel full, dropping client connection, ip: %s, icmp id: %d", ip.String(), icmpID)
		return nil
	}
	return conn
}

// writePacket writes an ICMP packet to the raw socket.
func (l *sharedListener) writePacket(dst net.IP, msg *icmp.Message) error {
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("error marshaling ICMP message: %w", err)
	}
	header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipHeaderSize,
		TotalLen: ipHeaderSize + len(msgBytes),
		Flags:    ipv4.DontFragment,
		TTL:      64,
		Protocol: protocolICMP,
		Dst:      dst.To4(),
	}
	if err := l.ip4Conn.WriteTo(header, msgBytes, nil); err != nil {
		return fmt.Errorf("error writing ICMP packet: %w", err)
	}
	return nil
}
