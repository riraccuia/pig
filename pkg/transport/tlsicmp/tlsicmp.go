package tlsicmp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/icmp"
)

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Conn, error) {
	tlsConn, err := newConn(conn, tlsConfig.Clone(), false)
	if err != nil {
		fmt.Println("failed to create TLS connection", err)
		return nil, err
	}
	return tlsConn, nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Listener, error) {
	listener := ice.NewListenerConn(co, func(conn net.Conn) (net.Conn, error) {
		return newConn(conn, tlsConfig.Clone(), true)
	})
	return listener, nil
}

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	icmpDialer := icmp.GetClientDialFunc(ctx, logger, config)

	return func() (transport.Conn, error) {
		// Get underlying ICMP connection
		icmpConn, err := icmpDialer()
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		tlsConn, err := newConn(icmpConn, tlsConfig.Clone(), false)
		if err != nil {
			logger.Errorf("failed to create TLS connection: %v", err)
			icmpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config
func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	icmpListenFunc := icmp.GetServerListenFunc(ctx, logger, config)

	return func() (transport.Listener, error) {
		// Create underlying ICMP listener
		icmpListener, err := icmpListenFunc()
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		return newListener(icmpListener, tlsConfig.Clone()), nil
	}
}
