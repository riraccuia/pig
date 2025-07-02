package ws

import (
	"context"
	"net"
	"net/http"

	"crypto/tls"

	"github.com/coder/websocket"
)

// WSListener implements transport.Listener for WebSocket connections
type WSListener struct {
	server   *http.Server
	ctx      context.Context
	connChan chan *WSConn
}

// NewWSListener creates a new WebSocket transport
func NewWSListener(ctx context.Context) *WSListener {
	return &WSListener{
		ctx:      ctx,
		connChan: make(chan *WSConn),
	}
}

func (t *WSListener) Accept() (net.Conn, error) {
	select {
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	case conn, ok := <-t.connChan:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (t *WSListener) Close() error {
	if t.server != nil {
		t.server.Close()
	}
	close(t.connChan)
	return nil
}

func (t *WSListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
func (t *WSListener) ListenWithListener(l net.Listener, tlsConfig *tls.Config) error {
	t.server = &http.Server{
		Handler:   t,
		TLSConfig: tlsConfig,
	}

	return t.server.Serve(tls.NewListener(l, tlsConfig))
}

// Listen starts the WebSocket server on the given address
func (t *WSListener) Listen(network, address string, tlsConfig *tls.Config) error {
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
