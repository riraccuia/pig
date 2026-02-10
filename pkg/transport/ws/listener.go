package ws

import (
	"context"
	"net"
	"net/http"
	"time"

	"crypto/tls"

	"github.com/coder/websocket"
)

// WSListener implements transport.Listener for WebSocket connections
type WSListener struct {
	server   *http.Server
	ctx      context.Context
	cancel   context.CancelCauseFunc
	connChan chan *WSConn
}

// NewWSListener creates a new WebSocket transport
func NewWSListener(ctx context.Context) *WSListener {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancelCause(ctx)

	return &WSListener{
		ctx:      ctx,
		cancel:   cancel,
		connChan: make(chan *WSConn),
	}
}

func (t *WSListener) Accept() (net.Conn, error) {
	if t.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	select {
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	case conn := <-t.connChan:
		conn.SetReadDeadline(time.Time{})
		return conn, nil
	}
}

func (t *WSListener) Close() error {
	if t.ctx.Err() != nil {
		return nil
	}
	t.cancel(net.ErrClosed)
	if t.server != nil {
		t.server.Close() // this will close the listener but not the websocket connection
	}
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
		ConnState: func(conn net.Conn, newState http.ConnState) {
			if newState != http.StateClosed {
				return
			}
			// This was a half-open connection, because it never got hijacked
			// so we need to close the listener to free the resources
			t.Close()
		},
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
