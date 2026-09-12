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
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/ipv4"
)

// Conn implements both transport.Conn and net.Conn interfaces.
type Conn struct {
	emss       uint32
	wantType   ipv4.ICMPType
	incoming   chan *Packet
	listener   *sharedListener
	localAddr  *net.IPAddr
	remoteAddr *net.IPAddr
	readBuf    *buffer
	writeBuf   *buffer
	ctx        context.Context
	cancel     context.CancelFunc
	// For tracking ICMP identifiers and sequence numbers.
	icmpID      uint16
	nextIcmpSeq atomic.Uint32
	recvIcmpSeq atomic.Uint32
	// For RTT tracking
	rtt    atomic.Int64 // Stores nanoseconds.
	rttvar atomic.Int64
	rtoSeq atomic.Value
	// for congestion control, fast retransmit,
	// fast recovery, etc.
	// NewReno algorithm.
	rq, ooq          *RetransmitQueue
	retransmit       atomic.Bool
	recovery         atomic.Bool
	transmitBlocked  bool
	transmitWg       *sync.Cond
	peerAck, peerSeq uint32
	prevPeerAck      uint32
	ack, seq         atomic.Uint32
	sentAck          atomic.Uint32
	ackTimer, rto    *time.Timer
	recover          atomic.Uint32
	cwnd             atomic.Uint32
	ssthresh         uint32
	flightSize       *FlightCounter
	dupCnt           uint8
	ackBytesCount    uint32
}

func Dial(ctx context.Context, logger common.Logger, bindAdapter, targetAddr string, icmpID uint16, isServer bool) (transport.Conn, error) {
	/*var (
		bindAddr *net.IPAddr
		iface    *net.Interface
		err      error
	)
	if bindAdapter != "" {
		bindAddr, iface, err = getAdapterAddr(bindAdapter)
		if err != nil {
			return nil, fmt.Errorf("failed to get adapter address: %w", err)
		}
	}*/
	return dial(ctx, logger, bindAdapter, targetAddr, icmpID, isServer)
}

// dial creates a new client connection to a target address.
func dial(ctx context.Context, logger common.Logger, bindAdapter, targetAddr string, icmpID uint16, isServer bool) (transport.Conn, error) {
	/*var (
		sharedListener *sharedListener
		err            error
	)*/

	err := setupGlobalListener(ctx, logger, bindAdapter, isServer)
	if err != nil {
		return nil, fmt.Errorf("failed to setup icmp listener: %w", err)
	}

	/*sharedListener, err = newSharedListener(ctx, logger, bindAddr, iface, isServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create shared listener: %w", err)
	}*/

	var (
		conn *Conn
		key  uint64
	)

	icmpID = icmpID & 0xffff

	if icmpID == 0 {
		icmpID = uint16(os.Getpid() & 0xffff)
	}

	// Create new connection
	conn = newConnection(
		ctx,
		globalListener,
		&net.IPAddr{IP: net.ParseIP(targetAddr)},
		icmpID,
	)

	// Register connection with listener
	key = getClientKey(conn.remoteAddr.IP, uint16(conn.icmpID))
	globalListener.clients.Store(key, conn)

	return conn, nil
}

// newConnection creates a new connection with shared read/write loops.
func newConnection(ctx context.Context, listener *sharedListener, remoteAddr *net.IPAddr, icmpID uint16) *Conn {
	connCtx, cancel := context.WithCancel(ctx)

	wantType := ipv4.ICMPTypeEchoReply
	if listener.isServer {
		wantType = ipv4.ICMPTypeEcho
	}

	c := &Conn{
		emss:       uint32(listener.mss - eHeaderSize),
		wantType:   wantType,
		incoming:   make(chan *Packet, 1024),
		listener:   listener,
		localAddr:  listener.localAddr,
		remoteAddr: remoteAddr,
		readBuf:    newBuffer((64 * 1024) << 2),
		writeBuf:   newBuffer((64 * 1024) << 2),
		ctx:        connCtx,
		cancel:     cancel,
		icmpID:     icmpID,
		ackTimer:   time.NewTimer(time.Millisecond * 300),
		rto:        time.NewTimer(time.Second),
	}

	// Initialize atomic values
	c.nextIcmpSeq.Store(0)
	c.recvIcmpSeq.Store(maxICMPSeq) // Initialize to last possible sequence number

	c.initNewReno()

	// Start the shared read/write loops
	go c.readLoop()
	go c.writeLoop()

	return c
}

// Connection interface implementation.
func (c *Conn) IsStreamed() bool {
	return false
}

func (c *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *Conn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) Close() error {
	c.sendCloseMessage()

	c.cancel()
	c.readBuf.Reset()
	c.writeBuf.Reset()

	// Remove from listener's client map
	key := getClientKey(c.remoteAddr.IP, uint16(c.icmpID))
	c.listener.clients.Delete(key)
	c.listener.logger.Infof("connection closed, ip: %s, icmp id: %d", c.remoteAddr.IP.String(), c.icmpID)
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	default:
		return c.readBuf.Read(b)
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	default:
		return c.writeBuf.Write(b)
	}
}

func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.readBuf.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.writeBuf.SetWriteDeadline(t)
}

// readLoop handles incoming data from the connection's incoming channel.
func (c *Conn) readLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.rto.C:
			c.listener.logger.Debugf("RTO expired, retransmitting missing segment, rtt: %v", c.GetRTT())
			c.rtt.Store(int64(c.GetRTT()) * 2) // double the RTT
			c.ssthresh = max(c.flightSize.Load()/2, 2*c.emss)
			c.cwnd.Store(c.emss)
			c.rto.Reset(c.GetRTT())
			c.retransmitMissingSegment(c.peerAck)
			c.recover.Store(c.seq.Load())
			c.retransmit.Store(false)
			c.unblockTransmit()
			continue
		case <-c.ackTimer.C:
			sentAck := c.sentAck.Load()
			ack := c.ack.Load()
			if sentAck == ack {
				break
			}
			// transport.Logger.Infof("ACK timer fired, acking, seq: %v, ack: %v", c.seq.Load(), ack)
			c.serializeAck(ack)
		case data := <-c.incoming:
			if err := c.processICMPPacket(data); err != nil {
				c.listener.logger.Errorf("Error processing ICMP packet: %v", err)
				c.Close()
				return
			}
			// c.listener.bufPool.Put(data)
		}

		// Timers management

		c.rto.Stop()
		c.ackTimer.Stop()

		if isUint32SeqHigher(c.seq.Load(), c.peerAck) {
			c.rto.Reset(c.GetRTT())
		}
		if isUint32SeqHigher(c.ack.Load(), c.sentAck.Load()) {
			c.ackTimer.Reset(time.Millisecond * 100)
		}
	}
}

// writeLoop handles outgoing data and sends it through the shared listener.
func (c *Conn) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// For clients, ensure we don't have too many outstanding ICMP packets
			/*if !c.listener.isServer {
				outstanding := uint16SeqDiff(c.nextIcmpSeq.Load(), c.recvIcmpSeq.Load())
				if outstanding >= maxOutstandingEchos {
					// transport.Logger.Infof("Outstanding echos: %d", outstanding)
					runtime.Gosched()
					continue
				}
			}

			// For servers, we can only reply to received sequences
			if c.listener.isServer {
				nextSeq := c.nextIcmpSeq.Load()
				expectedSeq := c.recvIcmpSeq.Load() + 1
				if isUint16SeqHigher(nextSeq, expectedSeq) {
					runtime.Gosched()
					continue
				}
			}*/

			// wait for recovery to complete
			c.waitTransmit()

			// Wait if we've reached the congestion window
			c.flightSize.WaitCwnd(c.emss)

			// Send application data
			if err := c.serializeOutboundData(); err != nil {
				c.listener.logger.Errorf("Error sending data: %v", err)
				continue
			}
		}
	}
}

// processICMPPacket handles the processing of a raw ICMP packet.
func (c *Conn) processICMPPacket(packet *Packet) error {
	if packet.IcmpType != c.wantType {
		c.listener.logger.Errorf("received unexpected icmp packet, %s", packet.IcmpPacket())
		return nil
	}

	if packet.IcmpCode == 255 {
		return fmt.Errorf("received close packet")
	}

	if packet.IcmpEchoID != c.icmpID {
		c.listener.logger.Errorf("received unexpected icmp packet, icmp id: %d, expected: %d", packet.IcmpEchoID, c.icmpID)
		return nil
	}

	// Validate and update ICMP sequence tracking
	// expectedSeq := c.recvIcmpSeq.Load() + 1
	c.recvIcmpSeq.Store(uint32(packet.IcmpSeq))

	if len(packet.IcmpPayload) < eHeaderSize {
		c.listener.clearMemory(packet.buffer)
		return nil // Ignore packets without seq/ack
	}

	//c.listener.logger.Infof("Received ICMP packet, seq: %d, len: %d", seq, len(data))

	//c.listener.logger.Infof("Received packet, seq: %d, ack: %d, len: %d", peerSeq, peerAck, len(data))

	if isUint32SeqHigher(c.peerSeq, packet.PacketSeq) {
		// drop spurious retransmissions
		return nil
	}

	// validate this is a valid peer sequence number
	if isUint32SeqHigher(packet.PacketSeq, c.peerSeq) {
		c.listener.logger.Tracef("Invalid peer seq: %s, WANT_SEQ: %d", packet.PigPacket(), c.peerSeq)
		if !c.recovery.Load() {
			c.listener.logger.Debug("Loss detected, entering recovery")
			c.recovery.Store(true)
			c.blockTransmit()
		}
	}

	if c.handleDuplicateAck(c.seq.Load(), packet) {
		return nil
	}

	// New ACK
	c.dupCnt = 0
	// Update RTT
	c.UpdateRTT(packet.PacketAck)
	// Update flight size and retransmit queue

	// transport.Logger.Infof("Peer acked %v bytes, flight size: %v", uint32SeqDiff(peerAck, c.peerAck), c.flightSize.Load())
	if !c.doFastRetransmit(packet.PacketAck) {
		c.updateCongestionWindow(packet.PacketAck)
	}

	if isUint32SeqHigher(packet.PacketAck, c.peerAck) {
		c.rq.DeleteUntil(packet.PacketAck)
		// deflate flight size
		c.flightSize.Sub(uint32SeqDiff(packet.PacketAck, c.peerAck))
		c.prevPeerAck = c.peerAck
		c.peerAck = packet.PacketAck
	}

	if len(packet.Data) == 0 {
		//c.listener.logger.Debugf("Received ACK, seq: %d, ack: %d", peerSeq, peerAck)
		return nil
	}

	if c.recovery.Load() {
		if c.peerSeq != packet.PacketSeq {
			c.listener.logger.Tracef("Received out of order packet in recovery %s", packet.PigPacket())
			c.ooq.Put(packet)
			c.serializeDuplicateAck(c.seq.Load(), c.sentAck.Load())
			return nil
		}
		// c.listener.logger.Debugf("Received packet in recovery %s", packet.PigPacket())
		// write data to read buffer
		c.readBuf.Write(packet.Data)
		// update our next peer sequence number
		c.peerSeq = packet.PacketSeq + uint32(len(packet.Data))
		c.listener.clearMemory(packet.buffer)
		c.recoverFromLoss(c.peerSeq)
		c.recovery.Store(false)
		// we can now resume transmitting
		c.unblockTransmit()
		return nil
	}

	// Process data
	if n, err := c.readBuf.Write(packet.Data); err != nil || n != len(packet.Data) {
		c.listener.logger.Errorf("error writing to read buffer: %v", err)
		return nil
	}

	// update our next peer sequence number
	c.peerSeq = packet.PacketSeq + uint32(len(packet.Data))
	// update our ack number
	c.ack.Store(c.peerSeq)

	c.listener.clearMemory(packet.buffer)

	lastSentAck := c.sentAck.Load()

	if uint32SeqDiff(c.peerSeq, lastSentAck) < 2*c.emss {
		return nil
	}

	c.serializeAck(c.peerSeq)

	return nil
}
