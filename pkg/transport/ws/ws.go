package ws

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"crypto/tls"

	"github.com/coder/websocket"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

// WSConn wraps a websocket connection to implement the transport.Conn interface
type WSConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
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

func (t *WSConn) LocalAddr() net.Addr {
	if t.localAddr == nil {
		return t.Conn.LocalAddr()
	}
	return t.localAddr
}

func (t *WSConn) RemoteAddr() net.Addr {
	if t.remoteAddr == nil {
		return t.Conn.RemoteAddr()
	}
	return t.remoteAddr
}

func (t *WSConn) IsStreamed() bool {
	return false
}

func (t *WSConn) Flush() {
	// WebSocket messages are sent immediately, no need for explicit flushing
}

func (t *WSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func (t *WSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func (t *WSTransport) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-t.connChan:
		return conn, nil
	}
}

func DialConn(ctx context.Context, conn net.Conn, address string, tlsConfig *tls.Config) (transport.Conn, error) {
	scheme := "ws"
	if tlsConfig != nil {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s", scheme, address)

	var httpClient *http.Client
	if tlsConfig != nil {
		httpClient = NewHTTPSClient(conn, tlsConfig)
	}

	if httpClient == nil {
		httpClient = NewHTTPClient(conn)
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, wsURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	return &WSConn{
		Conn:       netConn,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}, nil
}

func Dial(ctx context.Context, address string, tlsConfig *tls.Config) (transport.Conn, error) {
	scheme := "ws"
	if tlsConfig != nil {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s", scheme, address)

	httpClient := &http.Client{}
	if tlsConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
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
	return &WSConn{
		Conn: netConn,
	}, nil
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
	conn := &WSConn{Conn: netConn}

	select {
	case t.connChan <- conn:
	default:
		netConn.Close()
	}
}

// Listen starts the WebSocket server on the given address
func (t *WSTransport) ListenWithListener(l net.Listener, tlsConfig *tls.Config) error {
	t.server = &http.Server{
		Handler:   t,
		TLSConfig: tlsConfig,
	}

	return t.server.Serve(tls.NewListener(l, tlsConfig))
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

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Conn, error) {
	wsConn, err := DialConn(ctx, conn, conn.RemoteAddr().String(), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish WebSocket connection: %w", err)
	}
	return wsConn, nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.Config, tlsConfig *tls.Config) (transport.Listener, error) {
	tr := NewWSTransport()
	l := conn.NewTCPListener(co.LocalAddr().(*net.TCPAddr))
	l.Load(co)
	go tr.ListenWithListener(l, tlsConfig)
	return tr, nil
}

func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
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

func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		tr := NewWSTransport()
		go func() {
			err := tr.Listen(
				"ws",
				fmt.Sprintf(":%d", config.Target.Port),
				tlsConfig.Clone(),
			)
			if err != nil && err != http.ErrServerClosed {
				fmt.Printf("WebSocket server error: %v\n", err)
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
