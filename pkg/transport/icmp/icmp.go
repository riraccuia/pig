package icmp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/riraccuia/pig/pkg/common"
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

	globalListener       *sharedListener
	globalListenerDoOnce sync.Once
)

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		err := setupGlobalListener(ctx, logger, config.BindAdapter, false)
		if err != nil {
			return nil, fmt.Errorf("failed to setup icmp listener: %w", err)
		}

		// Create new connection
		conn := newConnection(
			ctx,
			globalListener,
			&net.IPAddr{IP: net.ParseIP(config.Target.Address)},
			uint16(os.Getpid()&0xffff),
		)

		// Register connection with listener
		key := getClientKey(conn.remoteAddr.IP, uint16(conn.icmpID))
		globalListener.clients.Store(key, conn)
		// Send initial keepalive
		/*if err := conn.sendEchoMessage(nil); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send initial keepalive: %w", err)
		}*/
		return conn, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config
func GetServerListenFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		if err := initSystem(); err != nil {
			return nil, fmt.Errorf("failed to initialize system: %w", err)
		}

		err := setupGlobalListener(ctx, logger, config.BindAdapter, true)
		if err != nil {
			return nil, fmt.Errorf("failed to setup icmp listener: %w", err)
		}

		return globalListener, nil
	}
}

func setupGlobalListener(ctx context.Context, logger common.Logger, bindAdapter string, isServer bool) (err error) {
	globalListenerDoOnce.Do(func() {
		var (
			bindAddr *net.IPAddr
			iface    *net.Interface
		)

		if bindAdapter != "" {
			bindAddr, iface, err = getAdapterAddr(bindAdapter)
			if err != nil {
				err = fmt.Errorf("failed to get adapter address: %w", err)
				return
			}
		}

		globalListener, err = newSharedListener(ctx, logger, bindAddr, iface, isServer)
		if err != nil {
			err = fmt.Errorf("failed to create shared listener: %w", err)
			return
		}
	})
	return
}
