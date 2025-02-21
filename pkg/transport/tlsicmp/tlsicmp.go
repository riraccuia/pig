package tlsicmp

import (
	"context"
	"crypto/tls"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/icmp"
)

// GetClientDialFunc returns a function that creates client connections based on config
func GetClientDialFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	icmpDialer := icmp.GetClientDialFunc(ctx, config)

	return func() (transport.Conn, error) {
		// Get underlying ICMP connection
		icmpConn, err := icmpDialer()
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		tlsConn, err := newConn(icmpConn, tlsConfig, true)
		if err != nil {
			icmpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config
func GetServerListenFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	icmpListenFunc := icmp.GetServerListenFunc(ctx, config)

	return func() (transport.Listener, error) {
		// Create underlying ICMP listener
		icmpListener, err := icmpListenFunc()
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		return newListener(icmpListener, tlsConfig), nil
	}
}
