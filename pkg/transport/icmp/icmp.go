package icmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

const (
	// Protocol number
	protocolICMP = 1

	// Default buffer sizes
	defaultBufferSize = (64 * 1024) << 6 //64KB buffer

	// Header sizes
	ipHeaderSize   = 20
	icmpHeaderSize = 8 // ICMP header (type + code + checksum + id + seq)
	eHeaderSize    = 8 // Encapsulation header (seq + ack)

	// Constants for NewReno congestion control
	maxOutstandingEchos = 20
	maxSequenceNumber   = ^uint32(0) - 65536 // Leave room for wrap-around
)

var (
	// Default MSS
	MSS uint32 = 1460
)

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, config *config.Config) func() (transport.Conn, error) {
	var sharedListener *sharedListener
	var initOnce sync.Once
	var initErr error

	return func() (transport.Conn, error) {
		initOnce.Do(func() {
			var bindAddr *net.IPAddr
			var iface *net.Interface
			var err error

			if config.BindAdapter != "" {
				bindAddr, iface, err = getAdapterAddr(config.BindAdapter)
				if err != nil {
					initErr = fmt.Errorf("failed to get adapter address: %w", err)
					return
				}
			}

			sharedListener, err = newSharedListener(ctx, bindAddr, iface)
			if err != nil {
				initErr = fmt.Errorf("failed to create shared listener: %w", err)
				return
			}
			sharedListener.isServer = false
		})

		if initErr != nil {
			return nil, initErr
		}

		// Create new connection
		conn := newConnection(
			ctx,
			sharedListener,
			&net.IPAddr{IP: net.ParseIP(config.Target.Address)},
			os.Getpid()&0xffff,
		)

		// Register connection with listener
		key := clientKey{
			ip:     conn.remoteAddr.(*net.IPAddr).IP.String(),
			icmpID: conn.icmpID,
		}
		sharedListener.clients.Store(key, conn)
		// Send initial keepalive
		/*if err := conn.sendEchoMessage(nil); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send initial keepalive: %w", err)
		}*/
		return conn, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config
func GetServerListenFunc(ctx context.Context, config *config.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		var bindAddr *net.IPAddr
		var iface *net.Interface
		var err error

		if config.BindAdapter != "" {
			bindAddr, iface, err = getAdapterAddr(config.BindAdapter)
			if err != nil {
				return nil, fmt.Errorf("failed to get adapter address: %w", err)
			}
		}

		if err := initSystem(); err != nil {
			return nil, fmt.Errorf("failed to initialize system: %w", err)
		}

		sharedListener, err := newSharedListener(ctx, bindAddr, iface)
		if err != nil {
			return nil, fmt.Errorf("failed to create shared listener: %w", err)
		}

		sharedListener.isServer = true

		return sharedListener, nil
	}
}

// processICMPPacket handles the processing of a raw ICMP packet
func (c *connection) processICMPPacket(dataBuf *rawSockBuffer) error {
	payload := dataBuf.b[dataBuf.po:dataBuf.len]

	// read icmp type
	icmpType := ipv4.ICMPType(payload[0])
	echoID := int(binary.BigEndian.Uint16(payload[4:6]))
	seq := uint32(binary.BigEndian.Uint16(payload[6:8]))
	// strip the icmp header
	data := payload[8:]

	if icmpType != c.wantType {
		transport.Logger.Errorf("received unexpected icmp packet, icmp type: %d, icmp id: %d, icmp seq: %d", icmpType, binary.BigEndian.Uint16(payload[4:6]), binary.BigEndian.Uint16(payload[6:8]))
		return nil
	}

	if echoID != c.icmpID {
		transport.Logger.Errorf("received unexpected icmp packet, icmp id: %d, expected: %d", echoID, c.icmpID)
		return nil
	}

	// Validate and update ICMP sequence tracking
	// expectedSeq := c.recvIcmpSeq.Load() + 1
	c.recvIcmpSeq.Store(seq)

	// transport.Logger.Infof("Received ICMP packet, seq: %d, len: %d", echo.Seq, len(echo.Data))

	if len(data) < 8 {
		return nil // Ignore packets without seq/ack
	}

	// Extract sequence and sequence and acknowledgment from payload
	peerSeq, peerAck := getSeqAck(data[:8])
	// strip our header
	data = data[8:]

	// transport.Logger.Infof("Received data packet, seq: %d, ack: %d, len: %d", peerSeq, peerAck, len(echo.Data))

	if len(data) == 0 && isUint32SeqHigher(c.peerAck, peerAck) {
		// the peer has already acked this data
		return nil
	}

	if isUint32SeqHigher(c.peerSeq, peerSeq) {
		// transport.Logger.Errorf("Received already acked packet (len: %d), got: %d, expected == %d. Peer seq: %d, peer ack: %d, last peer ack: %d", len(data), peerSeq, c.peerSeq, peerSeq, peerAck, c.peerAck)
		return nil
	}

	// validate this is a valid peer sequence number
	if c.peerSeq != peerSeq && len(data) > 0 { //isUint32SeqHigher(c.peerSeq.Load(), peerSeq) {
		c.recovery = true
		// transport.Logger.Infof("Sequence debug - received_seq: %d, peer_seq: %d, data_len: %d, last_ack: %d",
		//	peerSeq, c.peerSeq.Load(), len(echo.Data[8:]), c.ack.Load())
		transport.Logger.Errorf("Invalid peer seq number (cwnd:%v): got %d, expected == %d", c.cwnd.Load(), peerSeq, c.peerSeq)
		c.ooq.Put(dataBuf)
		c.serializeDuplicateAck(c.seq.Load(), c.peerSeq)
		return nil
	}

	// Handle acknowledgment
	if isUint32SeqHigher(peerAck, c.seq.Load()) {
		transport.Logger.Errorf("Invalid peer ack number: got %d, expected <= %d", peerAck, c.seq.Load())
		return nil
	}

	if c.handleDuplicateAck(c.seq.Load(), peerSeq, peerAck, data) {
		return nil
	}

	// New ACK
	c.dupCnt = 0
	// Update RTT
	c.UpdateRTT(peerAck)
	// Update flight size and retransmit queue
	c.rq.DeleteUntil(c.peerAck)
	// transport.Logger.Infof("Peer acked %v bytes, flight size: %v", uint32SeqDiff(peerAck, c.peerAck), c.flightSize.Load())
	c.doFastRetransmit(peerAck)
	c.updateCongestionWindow(peerAck)
	// deflate flight size
	c.flightSize.Sub(uint32SeqDiff(peerAck, c.peerAck))

	c.peerAck = peerAck

	// transport.Logger.Infof("Received data packet, seq: %d, ack: %d, len: %d", peerSeq, peerAck, len(echo.Data))

	if len(data) == 0 {
		// transport.Logger.Infof("Received empty ACK packet, len: %d, seq: %d, ack: %d", len(echo.Data), peerSeq, peerAck)
		return nil
	}

	// Process data
	if _, err := c.readBuf.Write(data); err != nil {
		transport.Logger.Errorf("error writing to read buffer: %v", err)
		return nil
	}

	c.ooq.DeleteUntil(c.peerSeq)

	// update our next peer sequence number
	c.peerSeq = peerSeq + uint32(len(data))
	// update our ack number
	c.ack.Store(c.peerSeq)

	if c.recovery {
		c.recoverFromLoss(c.peerSeq)
		return nil
	}

	lastSentAck := c.sentAck.Load()

	if uint32SeqDiff(c.peerSeq, lastSentAck) < 4*c.emss {
		return nil
	}

	// transport.Logger.Infof("Sending ACK, seq: %d, ack: %d, acked since last ack: %d", c.seq.Load(), c.peerSeq, uint32SeqDiff(c.peerSeq, c.sentAck.Load()))

	c.serializeAck(c.peerSeq)

	return nil
}

// drainOutOfOrderQueue processes packets in the out-of-order queue
// func (c *connection) drainOutOfOrderQueue() {

// }
// }

func getSeqAck(payload []byte) (uint32, uint32) {
	seq := binary.BigEndian.Uint32(payload[0:4])
	ack := binary.BigEndian.Uint32(payload[4:8])
	return seq, ack
}

func (c *connection) serializeDuplicateAck(seq, ack uint32) error {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], seq)
	binary.BigEndian.PutUint32(data[4:8], ack)

	if err := c.sendEchoMessage(data); err != nil {
		return fmt.Errorf("error sending duplicate ack: %w", err)
	}
	return nil
}

func (c *connection) serializeAck(ack uint32) error {
	lastSentAck := c.sentAck.Load()
	if lastSentAck == ack || isUint32SeqHigher(lastSentAck, ack) {
		return nil
	}

	if !c.sentAck.CompareAndSwap(lastSentAck, ack) {
		return nil
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], c.seq.Load())
	binary.BigEndian.PutUint32(data[4:8], ack)

	if err := c.sendEchoMessage(data); err != nil {
		return fmt.Errorf("error sending duplicate ack: %w", err)
	}

	// c.sentAck.Store(ack)
	return nil
}

func (c *connection) serializeRetransmitData(seq, ack uint32, data []byte) error {
	// binary.BigEndian.PutUint32(data[0:4], seq)
	binary.BigEndian.PutUint32(data[4:8], ack)

	if err := c.sendEchoMessage(data); err != nil {
		return fmt.Errorf("error sending retransmit data: %w", err)
	}
	return nil
}

// serializeData serializes the application data and sends it.
// It also updates the sequence number and adds the data to the retransmit queue.
// This is the only function that should be used to send application data.
func (c *connection) serializeData() error {
	rawBuf := c.listener.bufPool.Get().(*rawSockBuffer)
	rawBuf.po = 0
	rawBuf.len = icmpHeaderSize
	buf := rawBuf.b[icmpHeaderSize:]
	// Read data from buffer, limited by EMSS
	n, _ := c.writeBuf.Read(buf[eHeaderSize : eHeaderSize+c.emss])
	if n == 0 {
		return nil
	}

	rawBuf.len += 8 + n

	seq, ack := c.seq.Load(), c.ack.Load()

	// update the sent ack number
	c.sentAck.CompareAndSwap(c.sentAck.Load(), ack)
	// c.sentAck.Store(ack)

	// Prepare sequence and acknowledgment
	binary.BigEndian.PutUint32(buf[0:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ack)

	// Store in retransmit queue before sending
	// transport.Logger.Infof("Putting packet with seq %d, packets in queue: %d", seq, c.rq.Len())
	c.rq.Put(rawBuf)

	// Update sequence number and flight size
	c.seq.Add(uint32(n))
	c.flightSize.Add(uint32(n)) // Send data

	if err := c.sendEchoMessage(buf[:eHeaderSize+n]); err != nil {
		return fmt.Errorf("error sending data: %w", err)
	}

	c.rtoSeq.Store(&measurement{
		sendTime: time.Now(),
		seq:      c.seq.Load(),
	})
	// transport.Logger.Infof("Sent data packet, len: %d, nextseq: %d, ack: %d", n, c.seq.Load(), c.ack.Load())

	return nil
}

// sendEchoMessage sends an ICMP echo request with the given data
func (c *connection) sendEchoMessage(data []byte) error {
	seq := c.nextIcmpSeq.Load()
	c.nextIcmpSeq.Add(1)

	icmpType := ipv4.ICMPTypeEcho
	if c.listener.isServer {
		icmpType = ipv4.ICMPTypeEchoReply
	}

	msg := &icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   c.icmpID,
			Seq:  int(seq),
			Data: data,
		},
	}

	// transport.Logger.Infof("Sending echo, seq: %d, cwnd: %d", seq, c.cwnd.Load())

	return c.listener.writePacket(c.remoteAddr.(*net.IPAddr).IP.To4(), msg)
}
