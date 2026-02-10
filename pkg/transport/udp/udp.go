package udp

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

// defaultBufferSize is the UDP buffer size, initialized to 64KB by default
// On Darwin systems, this will be updated to the system's net.inet.udp.maxdgram value
var defaultBufferSize = 64 * 1024

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig) func() (transport.Conn, error) {
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
func GetServerListenFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig) func() (transport.Listener, error) {
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
