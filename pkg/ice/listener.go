package ice

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/riraccuia/pig/pkg/transport"
)

// Listener is a wrapper listener that joins multiple listeners into one.
// It is useful to handle multiple addresses and protocols.
// It implements the transport.Listener interface.
type Listener struct {
	acceptChan chan transport.Conn
	localAddr  net.Addr
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
}

func NewListener(ctx context.Context, localAddr net.Addr) *Listener {
	innerCtx, cancel := context.WithCancel(ctx)
	return &Listener{
		acceptChan: make(chan transport.Conn),
		localAddr:  localAddr,
		ctx:        innerCtx,
		cancel:     cancel,
	}
}

func (l *Listener) Addr() net.Addr {
	return l.localAddr
}

func (l *Listener) Load(listener transport.Listener) error {
	if l.closed.Load() {
		return net.ErrClosed
	}
	go l.processChildListener(listener)
	return nil
}

func (l *Listener) Accept(ctx context.Context) (transport.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case co, ok := <-l.acceptChan:
		if !ok {
			return nil, net.ErrClosed
		}
		return co, nil
	}
}

func (l *Listener) processChildListener(listener transport.Listener) {
	for {
		co, err := listener.Accept(l.ctx)
		if err != nil {
			return
		}

		select {
		case <-l.ctx.Done():
			return
		case l.acceptChan <- co:
		}
	}
}

func (l *Listener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	l.cancel()
	close(l.acceptChan)
	l.acceptChan = nil
	return nil
}
