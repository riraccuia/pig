package icmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/riraccuia/pig/pkg/packet"
	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// sharedListener handles the raw ICMP socket and connection dispatching
type sharedListener struct {
	isServer   bool
	ip4Conn    *ipv4.RawConn
	conn       *net.IPConn
	localAddr  net.Addr
	ctx        context.Context
	cancel     context.CancelFunc
	mss        int
	clients    sync.Map // map[clientKey]*connection
	connChan   chan transport.Conn
	packetChan chan *icmpPacket
	bufPool    sync.Pool
}

// icmpPacket represents a processed ICMP packet ready for dispatch
type icmpPacket struct {
	dst    net.IP
	buffer *rawSockBuffer
}

// clientKey uniquely identifies a client connection
type clientKey struct {
	ip     string
	icmpID int
}

// newSharedListener creates a new shared ICMP socket listener
func newSharedListener(ctx context.Context, bindAddr *net.IPAddr, iface *net.Interface) (*sharedListener, error) {
	conn, err := net.ListenIP("ip4:icmp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket: %w", err)
	}

	ip4Conn, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create raw connection: %w", err)
	}

	ip4Conn.SetWriteBuffer(defaultBufferSize)
	ip4Conn.SetReadBuffer(defaultBufferSize)

	listenerCtx, cancel := context.WithCancel(ctx)
	l := &sharedListener{
		ip4Conn:    ip4Conn,
		conn:       conn,
		localAddr:  conn.LocalAddr(),
		ctx:        listenerCtx,
		cancel:     cancel,
		mss:        iface.MTU - ipHeaderSize - icmpHeaderSize,
		connChan:   make(chan transport.Conn, 1024),
		packetChan: make(chan *icmpPacket, 1024),
		bufPool:    sync.Pool{New: func() any { return &rawSockBuffer{b: make([]byte, iface.MTU)} }},
	}

	// Start the packet dispatch loop
	go l.dispatchPackets()
	runtime.Gosched()
	// Start the packet reading loop
	go l.readPackets()

	return l, nil
}

// Accept implements the Listener interface
func (l *sharedListener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.ctx.Done():
		return nil, fmt.Errorf("listener closed")
	case conn := <-l.connChan:
		return conn, nil
	}
}

// Close implements the Listener interface
func (l *sharedListener) Close() error {
	l.cancel()
	l.clients.Range(func(key, value interface{}) bool {
		conn := value.(*connection)
		conn.Close()
		l.clients.Delete(key)
		return true
	})
	return l.conn.Close()
}

type rawSockBuffer struct {
	b   []byte
	len int // end of data
	po  int // payload offset
}

// readPackets continuously reads ICMP packets and processes them for the listener
func (l *sharedListener) readPackets() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
			// buffer := make([]byte, l.mtu)
			buffer := l.bufPool.Get().(*rawSockBuffer)

			n, _, _, ipSrc, err := l.conn.ReadMsgIP(buffer.b, nil)
			if err != nil {
				transport.Logger.Errorf("Error reading ICMP packet: %v", err)
				l.bufPool.Put(buffer)
				continue
			}

			pkt := packet.IPv4Packet(buffer.b[:n])
			payload := buffer.b[pkt.PayloadOffset():n]

			buffer.len = n
			buffer.po = pkt.PayloadOffset()

			//if lenFromIPHeader+ipHeaderSize != uint16(n) {
			//transport.Logger.Infof("hex dump (len: %d vs %d): \n%x", n, lenFromIPHeader+ipHeaderSize, buffer[0:20])
			//}

			select {
			case l.packetChan <- &icmpPacket{
				dst:    ipSrc.IP.To4(),
				buffer: buffer,
			}:
			default:
				transport.Logger.Errorf("packet channel full, dropping packet, icmp type: %d, icmp id: %d, icmp seq: %d", ipv4.ICMPType(payload[0]), binary.BigEndian.Uint16(payload[4:6]), binary.BigEndian.Uint16(payload[6:8]))
			}

			// buffer := l.bufPool.Get().([]byte)

			// header, payload, _, err := l.ip4Conn.ReadFrom(buffer)
			// if err != nil {
			// transport.Logger.Errorf("Error reading ICMP packet: %v", err)
			// continue
			// }

			// if header.Protocol != protocolICMP {
			// transport.Logger.Infof("received non-icmp packet, protocol: %d", header.Protocol)
			// continue
			// }

			// // transport.Logger.Infof("received icmp packet, icmp type: %d, icmp id: %d, icmp seq: %d", ipv4.ICMPType(payload[0]), binary.BigEndian.Uint16(payload[4:6]), binary.BigEndian.Uint16(payload[6:8]))

			// select {
			// case l.packetChan <- &icmpPacket{
			// header:  header,
			// payload: payload,
			// }:
			// default:
			// transport.Logger.Errorf("packet channel full, dropping packet, icmp type: %d, icmp id: %d, icmp seq: %d", ipv4.ICMPType(payload[0]), binary.BigEndian.Uint16(payload[4:6]), binary.BigEndian.Uint16(payload[6:8]))
			// }
		}
	}
}

// dispatchPackets handles dispatching ICMP packets to their respective connections
func (l *sharedListener) dispatchPackets() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case packet := <-l.packetChan:
			//transport.Logger.Infof("dispatching packet, icmp type: %d, icmp id: %d, icmp seq: %d", ipv4.ICMPType(packet.payload[0]), binary.BigEndian.Uint16(packet.payload[4:6]), binary.BigEndian.Uint16(packet.payload[6:8]))

			payload := packet.buffer.b[packet.buffer.po:packet.buffer.len]

			// read icmp type from the first byte of the icmp payload
			icmpType := ipv4.ICMPType(payload[0])
			// read icmp id from icmp payload
			icmpID := binary.BigEndian.Uint16(payload[4:6])

			if l.isServer && icmpType != ipv4.ICMPTypeEcho {
				transport.Logger.Errorf("received non-echo request, icmp type: %d", icmpType)
				continue
			}
			if !l.isServer && icmpType != ipv4.ICMPTypeEchoReply {
				transport.Logger.Errorf("received non-echo reply, icmp type: %d", icmpType)
				continue
			}

			key := clientKey{
				ip:     packet.dst.String(),
				icmpID: int(icmpID),
			}

			var conn *connection
			conn = l.getClientConn(packet.dst, key)

			if conn == nil {
				continue
			}

			// Forward packet to the appropriate connection
			select {
			case conn.incoming <- packet.buffer:
				// transport.Logger.Infof("forwarded packet to connection, ip: %s, icmp id: %d, icmp seq: %d", packet.header.Src.String(), icmpID, binary.BigEndian.Uint16(packet.payload[6:8]))
			default:
				transport.Logger.Errorf("Connection buffer full, dropping packet")
			}
		}
	}
}

func (l *sharedListener) getClientConn(ip net.IP, key clientKey) *connection {
	_conn, exists := l.clients.Load(key)
	if exists {
		return _conn.(*connection)
	}

	transport.Logger.Infof("tracking new client connection, ip: %s, icmp id: %d", key.ip, key.icmpID)

	conn := newConnection(
		l.ctx,
		l,
		&net.IPAddr{IP: ip},
		key.icmpID,
	)

	l.clients.Store(key, conn)

	select {
	case l.connChan <- conn:
	default:
		conn.Close()
		l.clients.Delete(key)
		transport.Logger.Errorf("Accept channel full, dropping client connection, ip: %s, icmp id: %d", ip.String(), key.icmpID)
		return nil
	}
	return conn
}

// writePacket writes an ICMP packet to the raw socket
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
