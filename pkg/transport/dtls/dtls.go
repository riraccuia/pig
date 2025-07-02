package dtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

// GetClientFromConn creates a DTLS client connection from an existing connection
func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Conn, error) {
	// Convert TLS config to DTLS config
	dtlsConfig := &dtls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		ServerName:         tlsConfig.ServerName,
		MTU:                config.MTU,
	}

	if len(tlsConfig.Certificates) > 0 {
		dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
	}

	if tlsConfig.RootCAs != nil {
		dtlsConfig.RootCAs = tlsConfig.RootCAs
	}

	dtlsConn, err := DialConn(ctx, conn, conn.RemoteAddr().String(), dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}
	return dtlsConn, nil
}

// GetListenerFromConn creates a DTLS listener from an existing connection
func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Listener, error) {
	// Convert TLS config to DTLS config
	dtlsConfig := &dtls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		ServerName:         tlsConfig.ServerName,
		MTU:                config.MTU,
	}

	if len(tlsConfig.Certificates) > 0 {
		dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
	}

	if tlsConfig.ClientCAs != nil {
		dtlsConfig.ClientCAs = tlsConfig.ClientCAs
	}

	listenerConn := ice.NewPacketListenerConn(co, nil)
	dtlsListener, err := dtls.NewListener(listenerConn, dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
	}
	return NewDTLSListener(dtlsListener), nil
}

// GetClientDialFunc returns a function that creates DTLS client connections
func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		// Convert TLS config to DTLS config
		dtlsConfig := &dtls.Config{
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         tlsConfig.ServerName,
			MTU:                config.MTU,
		}

		if len(tlsConfig.Certificates) > 0 {
			dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
		}

		if tlsConfig.RootCAs != nil {
			dtlsConfig.RootCAs = tlsConfig.RootCAs
		}

		conn, err := Dial(
			ctx,
			fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port),
			dtlsConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
		}
		return conn, nil
	}
}

// GetServerListenFunc returns a function that creates DTLS server listeners
func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		// Convert TLS config to DTLS config
		dtlsConfig := &dtls.Config{
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         tlsConfig.ServerName,
			MTU:                config.MTU,
		}

		if len(tlsConfig.Certificates) > 0 {
			dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
		}

		if tlsConfig.ClientCAs != nil {
			dtlsConfig.ClientCAs = tlsConfig.ClientCAs
		}

		listener, err := Listen(
			"udp",
			fmt.Sprintf(":%d", config.Target.Port),
			dtlsConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
		}
		return listener, nil
	}
}
