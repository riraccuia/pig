package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	tlsConn := tls.Client(co, tlsConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("failed to handshake: %w", err)
	}
	return NewTLSConn(tlsConn), nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Listener, error) {
	tlsConn := tls.Server(co, tlsConfig.Clone())
	return ice.NewListenerConn(NewTLSConn(tlsConn), nil), nil
}

func GetClientDialFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		addr := fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port)
		dialer := &net.Dialer{}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to establish TLS connection: %w", err)
		}
		return NewTLSConn(conn), nil
	}
}

func GetServerListenFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		addr := fmt.Sprintf(":%d", config.Target.Port)
		listener, err := tls.Listen("tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS listener: %w", err)
		}
		return NewTLSListener(listener), nil
	}
}
