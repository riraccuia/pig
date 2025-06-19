package udp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

// defaultBufferSize is the UDP buffer size, initialized to 64KB by default
// On Darwin systems, this will be updated to the system's net.inet.udp.maxdgram value
var defaultBufferSize = 64 * 1024

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config) func() (transport.Conn, error) {
	initUDP(logger)
	return func() (transport.Conn, error) {
		addr := fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port)
		conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", config.Target.SrcPort))
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket: %w", err)
		}

		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
		}

		// Create a new connection with a read buffer and context
		c := &connection{
			conn:     conn,
			raddr:    raddr,
			readChan: make(chan []byte, defaultBufferSize/1024), // Scale buffer count based on size
			ctx:      ctx,
		}

		// Start the read loop for the client connection
		go func() {
			readBuffer := make([]byte, defaultBufferSize)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					n, _, err := conn.ReadFrom(readBuffer)
					if err != nil {
						if !strings.Contains(err.Error(), "use of closed network connection") {
							logger.Errorf("UDP client read error: %v", err)
						}
						return
					}

					data := make([]byte, n)
					copy(data, readBuffer[:n])
					select {
					case c.readChan <- data:
					default:
						logger.Errorf("UDP client data channel full, dropping packet")
					}
				}
			}
		}()

		return c, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config
func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config) func() (transport.Listener, error) {
	initUDP(logger)
	return func() (transport.Listener, error) {
		addr := fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port)
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on UDP: %w", err)
		}

		return newListener(logger, conn, conn.LocalAddr()), nil
	}
}

// listener implements the transport.Listener interface
type listener struct {
	conn       net.PacketConn
	addr       net.Addr
	connChan   chan transport.Conn
	addrConns  map[string]*connection
	mu         sync.RWMutex
	readBuffer []byte
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *log.Logger
}

func newListener(logger *log.Logger, conn net.PacketConn, addr net.Addr) *listener {
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

func (l *listener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
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

// connection implements the transport.Conn interface
type connection struct {
	conn       net.PacketConn
	raddr      net.Addr
	readChan   chan []byte
	ctx        context.Context
	readBuffer []byte // Buffer for partially read data
}

func (c *connection) IsStreamed() bool {
	return false
}

func (c *connection) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) Read(b []byte) (n int, err error) {
	// If we have leftover data from a previous read, use that first
	if len(c.readBuffer) > 0 {
		n = copy(b, c.readBuffer)
		if n < len(c.readBuffer) {
			// Buffer b was too small, keep the remaining data
			c.readBuffer = c.readBuffer[n:]
		} else {
			// All data was copied, clear the buffer
			c.readBuffer = nil
		}
		return n, nil
	}

	// No leftover data, read from channel
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	case data, ok := <-c.readChan:
		if !ok {
			return 0, fmt.Errorf("connection closed")
		}
		n = copy(b, data)
		if n < len(data) {
			// Buffer b was too small, store the remaining data
			c.readBuffer = make([]byte, len(data)-n)
			copy(c.readBuffer, data[n:])
		}
		return n, nil
	}
}

func (c *connection) Write(b []byte) (n int, err error) {
	if c.raddr == nil {
		return 0, fmt.Errorf("no remote address set for UDP connection")
	}
	return c.conn.WriteTo(b, c.raddr)
}

func (c *connection) Close() error {
	return c.conn.Close()
}

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
