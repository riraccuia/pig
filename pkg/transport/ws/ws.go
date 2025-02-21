package ws

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"crypto/tls"

	"github.com/coder/websocket"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

// WSConn wraps a websocket connection to implement the transport.Conn interface
type WSConn struct {
	conn net.Conn
}

// WSTransport implements transport.Listener and transport.Dialer for WebSocket connections
type WSTransport struct {
	server   *http.Server
	connChan chan *WSConn
}

// NewWSTransport creates a new WebSocket transport
func NewWSTransport() *WSTransport {
	return &WSTransport{
		connChan: make(chan *WSConn),
	}
}

func (t *WSConn) IsStreamed() bool {
	return false
}

func (t *WSConn) Read(b []byte) (n int, err error) {
	return t.conn.Read(b)
}

func (t *WSConn) Write(b []byte) (n int, err error) {
	return t.conn.Write(b)
}

func (t *WSConn) Flush() {
	// WebSocket messages are sent immediately, no need for explicit flushing
}

func (t *WSConn) Close() error {
	return t.conn.Close()
}

func (t *WSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func (t *WSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func (t *WSConn) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *WSConn) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

func (t *WSTransport) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-t.connChan:
		return conn, nil
	}
}

func (t *WSTransport) Dial(ctx context.Context, network string, address string, config any) (transport.Conn, error) {
	scheme := "ws"
	if config != nil {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s", scheme, address)

	httpClient := &http.Client{}
	if config != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: config.(*tls.Config),
		}
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, wsURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	return &WSConn{conn: netConn}, nil
}

func (t *WSTransport) Close() error {
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}

func (t *WSTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	conn := &WSConn{conn: netConn}

	select {
	case t.connChan <- conn:
	default:
		netConn.Close()
	}
}

// Listen starts the WebSocket server on the given address
func (t *WSTransport) Listen(network, address string, tlsConfig *tls.Config) error {
	t.server = &http.Server{
		Addr:      address,
		Handler:   t,
		TLSConfig: tlsConfig,
	}

	if tlsConfig != nil {
		return t.server.ListenAndServeTLS("", "")
	}
	return t.server.ListenAndServe()
}

func GetClientDialFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		transport := NewWSTransport()
		conn, err := transport.Dial(
			ctx,
			"ws",
			fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port),
			tlsConfig.Clone(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish WebSocket connection: %w", err)
		}
		return conn, nil
	}
}

func GetServerListenFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		transport := NewWSTransport()
		go func() {
			err := transport.Listen(
				"ws",
				fmt.Sprintf(":%d", config.Target.Port),
				tlsConfig.Clone(),
			)
			if err != nil && err != http.ErrServerClosed {
				fmt.Printf("WebSocket server error: %v\n", err)
			}
		}()
		return transport, nil
	}
}
