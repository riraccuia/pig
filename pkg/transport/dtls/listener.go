package dtls

import (
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/transport"
)

// DTLSListener wraps a DTLS listener to implement the transport.Listener interface
type DTLSListener struct {
	listener net.Listener
}

// NewDTLSListener creates a new DTLS listener wrapper
func NewDTLSListener(listener net.Listener) *DTLSListener {
	return &DTLSListener{listener: listener}
}

// Implement transport.Listener interface methods
func (l *DTLSListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return nil, fmt.Errorf("accepted connection is not a DTLS connection")
	}
	return NewDTLSConn(dtlsConn), nil
}

func (l *DTLSListener) Close() error {
	return l.listener.Close()
}

// Listen creates a DTLS listener on the given address
func Listen(network, address string, dtlsConfig *dtls.Config) (transport.Listener, error) {
	// Parse the address
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	listener, err := dtls.Listen(network, laddr, dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
	}

	return NewDTLSListener(listener), nil
}
