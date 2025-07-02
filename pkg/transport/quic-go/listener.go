package quicgo

import (
	"context"
	"net"

	"github.com/quic-go/quic-go"
)

type QuicListener struct {
	ctx      context.Context
	listener *quic.Listener
}

func NewQuicTransport(ctx context.Context, listener *quic.Listener) *QuicListener {
	return &QuicListener{ctx: ctx, listener: listener}
}

func (t *QuicListener) Accept() (net.Conn, error) {
	conn, err := t.listener.Accept(t.ctx)
	if err != nil {
		return nil, err
	}
	return NewQuicConn(conn), nil
}

func (t *QuicListener) Close() error {
	return t.listener.Close()
}
