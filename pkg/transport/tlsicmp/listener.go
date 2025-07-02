package tlsicmp

import (
	"crypto/tls"
	"net"

	"github.com/riraccuia/pig/pkg/transport"
)

// listener implements transport.Listener by wrapping an ICMP listener with TLS
type listener struct {
	icmpListener transport.Listener
	tlsConfig    *tls.Config
}

// newListener creates a new TLS-over-ICMP listener
func newListener(icmpListener transport.Listener, tlsConfig *tls.Config) *listener {
	return &listener{
		icmpListener: icmpListener,
		tlsConfig:    tlsConfig,
	}
}

// Accept implements transport.Listener
func (l *listener) Accept() (net.Conn, error) {
	// Accept underlying ICMP connection
	icmpConn, err := l.icmpListener.Accept()
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn, err := newConn(icmpConn, l.tlsConfig, false)
	if err != nil {
		icmpConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Close implements transport.Listener
func (l *listener) Close() error {
	return l.icmpListener.Close()
}
