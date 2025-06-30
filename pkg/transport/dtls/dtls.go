package dtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

// DTLSConn wraps a DTLS connection to implement the transport.Conn interface
type DTLSConn struct {
	*dtls.Conn
}

// DTLSListener wraps a DTLS listener to implement the transport.Listener interface
type DTLSListener struct {
	listener net.Listener
}

// UDPListener wraps a UDP listener to work with DTLS
type UDPListener struct {
	acceptChan chan net.Conn
	localAddr  *net.UDPAddr
}

// NewUDPListener creates a new UDP listener wrapper
func NewUDPListener(localAddr *net.UDPAddr) *UDPListener {
	return &UDPListener{
		acceptChan: make(chan net.Conn, 32),
		localAddr:  localAddr,
	}
}

func (l *UDPListener) Addr() net.Addr {
	return l.localAddr
}

func (l *UDPListener) Load(conn net.Conn) error {
	select {
	case l.acceptChan <- conn:
		return nil
	default:
		conn.Close()
		return fmt.Errorf("accept channel is full")
	}
}

func (l *UDPListener) Accept() (net.PacketConn, net.Addr, error) {
	conn, ok := <-l.acceptChan
	if !ok {
		return nil, nil, net.ErrClosed
	}
	return conn.(net.PacketConn), conn.RemoteAddr(), nil
}

func (l *UDPListener) Close() error {
	close(l.acceptChan)
	return nil
}

// NewDTLSConn creates a new DTLS connection wrapper
func NewDTLSConn(dtlsConn *dtls.Conn) *DTLSConn {
	return &DTLSConn{Conn: dtlsConn}
}

// NewDTLSListener creates a new DTLS listener wrapper
func NewDTLSListener(listener net.Listener) *DTLSListener {
	return &DTLSListener{listener: listener}
}

// Implement transport.Conn interface methods
func (c *DTLSConn) IsStreamed() bool {
	return false
}

func (c *DTLSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *DTLSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *DTLSConn) Flush() {
	// DTLS connections don't need explicit flushing
}

// Implement transport.Listener interface methods
func (l *DTLSListener) Accept(ctx context.Context) (transport.Conn, error) {
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

// Dial establishes a DTLS connection to the given address
func Dial(ctx context.Context, address string, dtlsConfig *dtls.Config) (transport.Conn, error) {
	// Parse the address
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := dtls.Dial("udp", raddr, dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}

	return NewDTLSConn(conn), nil
}

// DialConn establishes a DTLS connection using an existing UDP connection
func DialConn(ctx context.Context, conn net.Conn, address string, dtlsConfig *dtls.Config) (transport.Conn, error) {
	// Use the existing connection to establish DTLS
	dtlsConn, err := dtls.Client(conn.(net.PacketConn), conn.RemoteAddr(), dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}

	return NewDTLSConn(dtlsConn), nil
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

	listener := NewUDPListener(co.LocalAddr().(*net.UDPAddr))
	listener.Load(co)
	dtlsListener, err := dtls.NewListener(listener, dtlsConfig)
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
