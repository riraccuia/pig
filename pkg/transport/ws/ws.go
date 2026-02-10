package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	wsConn, err := DialConn(ctx, conn, conn.RemoteAddr().String(), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish WebSocket connection: %w", err)
	}
	return wsConn, nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Listener, error) {
	co.SetReadDeadline(time.Now().Add(time.Second * 10))
	tr := NewWSListener(ctx)
	l := ice.NewListenerConn(co, nil)
	go tr.ListenWithListener(l, tlsConfig)
	return tr, nil
}

func GetClientDialFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		conn, err := Dial(
			ctx,
			fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port),
			tlsConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish WebSocket connection: %w", err)
		}
		return conn, nil
	}
}

func GetServerListenFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		tr := NewWSListener(ctx)
		go func() {
			err := tr.Listen(
				"ws",
				fmt.Sprintf(":%d", config.Target.Port),
				tlsConfig.Clone(),
			)
			if err != nil && err != http.ErrServerClosed {
				logger.Errorf("WebSocket server error: %v", err)
			}
		}()
		return tr, nil
	}
}

// NewHTTPSClient creates a new HTTPS client that uses a TCP connection
func NewHTTPSClient(conn net.Conn, tlsConfig *tls.Config) *http.Client {
	return newHTTPClient(conn, tlsConfig)
}

// NewHTTPClient creates a new HTTP client that uses a TCP connection
func NewHTTPClient(conn net.Conn) *http.Client {
	return newHTTPClient(conn, nil)
}

// newHTTPClient creates a new HTTP client that uses a TCP connection,
// if a tlsConfig is provided, it will create a TLS connection, otherwise it will use
// the provided connection as is.
func newHTTPClient(conn net.Conn, tlsConfig *tls.Config) *http.Client {
	var (
		httpConn  net.Conn
		transport = &http.Transport{
			DisableKeepAlives:  true,
			DisableCompression: true,
		}
	)

	if tlsConfig != nil {
		// Create TLS connection
		httpConn = tls.Client(conn, tlsConfig)
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return httpConn, nil
		}
	}

	if httpConn == nil {
		httpConn = conn
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return httpConn, nil
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}
