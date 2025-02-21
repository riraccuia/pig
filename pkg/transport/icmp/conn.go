package icmp

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/ipv4"
)

// connection implements both transport.Conn and net.Conn interfaces
type connection struct {
	emss       uint32
	wantType   ipv4.ICMPType
	incoming   chan *rawSockBuffer
	listener   *sharedListener
	localAddr  net.Addr
	remoteAddr net.Addr
	readBuf    *buffer
	writeBuf   *buffer
	ctx        context.Context
	cancel     context.CancelFunc
	// For tracking ICMP identifiers and sequence numbers
	icmpID      int
	nextIcmpSeq atomic.Uint32
	recvIcmpSeq atomic.Uint32
	// For RTT tracking
	rtt    atomic.Int64 // Stores nanoseconds
	rttvar atomic.Int64
	rtoSeq atomic.Value
	// for congestion control, fast retransmit,
	// fast recovery, etc.
	// NewReno algorithm
	rq, ooq          *RetransmitQueue
	retransmit       atomic.Bool
	recovery         bool
	peerAck, peerSeq uint32
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

// newConnection creates a new connection with shared read/write loops
func newConnection(ctx context.Context, listener *sharedListener, remoteAddr net.Addr, icmpID int) *connection {
	connCtx, cancel := context.WithCancel(ctx)

	wantType := ipv4.ICMPTypeEchoReply
	if listener.isServer {
		wantType = ipv4.ICMPTypeEcho
	}

	c := &connection{
		emss:       uint32(listener.mss - eHeaderSize),
		wantType:   wantType,
		incoming:   make(chan *rawSockBuffer, 1024),
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

// Connection interface implementation
func (c *connection) IsStreamed() bool {
	return false
}

func (c *connection) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *connection) Close() error {
	c.cancel()
	c.readBuf = nil
	c.writeBuf = nil

	// Remove from listener's client map
	key := clientKey{
		ip:     c.remoteAddr.(*net.IPAddr).IP.String(),
		icmpID: c.icmpID,
	}
	c.listener.clients.Delete(key)
	return nil
}

func (c *connection) Read(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	default:
		return c.readBuf.Read(b)
	}
}

func (c *connection) Write(b []byte) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	default:
		return c.writeBuf.Write(b)
	}
}

// readLoop handles incoming data from the connection's incoming channel
func (c *connection) readLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.rto.C:
			transport.Logger.Debugf("RTO expired, retransmitting missing segment, rtt: %v", c.GetRTT())
			c.rtt.Store(int64(c.GetRTT()) * 2) // double the RTT
			c.ssthresh = min(c.flightSize.Load()/2, 2*c.emss)
			c.cwnd.Store(c.emss)
			c.retransmitMissingSegment(c.peerAck)
			if c.retransmit.Load() {
				c.retransmit.Store(false)
			}
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
				transport.Logger.Errorf("Error processing ICMP packet: %v", err)
			}
			// c.listener.bufPool.Put(data)
		}

		// Timers management

		c.rto.Stop()
		c.ackTimer.Stop()

		if isUint32SeqHigher(c.seq.Load(), c.peerAck) {
			if c.peerAck == maxUint32Seq {
				continue
			}
			// transport.Logger.Infof("Current RTT is: %v", c.GetRTT())
			c.rto.Reset(c.GetRTT())
		}
		if isUint32SeqHigher(c.peerSeq, c.sentAck.Load()) {
			c.ackTimer.Reset(time.Millisecond * 100)
			continue
		}
	}
}

// writeLoop handles outgoing data and sends it through the shared listener
func (c *connection) writeLoop() {
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

			// Wait if we've reached the congestion window
			c.flightSize.WaitCwnd()

			// Send application data
			if err := c.serializeData(); err != nil {
				transport.Logger.Errorf("Error sending data: %v", err)
				continue
			}
		}
	}
}
