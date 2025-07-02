package ice

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/riraccuia/pig/pkg/transport"
)

// Listener is a wrapper listener that joins multiple listeners into one.
// It is useful to handle multiple addresses and protocols.
// It implements the transport.Listener interface.
type Listener struct {
	acceptChan chan net.Conn
	localAddr  net.Addr
	ctx        context.Context
	cancel     context.CancelFunc
	closed     atomic.Bool
}

func NewListener(ctx context.Context, localAddr net.Addr) *Listener {
	innerCtx, cancel := context.WithCancel(ctx)
	return &Listener{
		acceptChan: make(chan net.Conn),
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

func (l *Listener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	case co, ok := <-l.acceptChan:
		if !ok {
			return nil, net.ErrClosed
		}
		return co, nil
	}
}

func (l *Listener) processChildListener(listener transport.Listener) {
	for {
		co, err := listener.Accept()
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

// ListenerConn is a listener that wraps a net.Conn and applies a control function to it.
// It is useful to apply a control function to a connection before it is returned to the user.
// It implements the net.Listener interface.
type ListenerConn struct {
	conn    net.Conn
	Control func(net.Conn) (net.Conn, error)
}

func NewListenerConn(conn net.Conn, control func(net.Conn) (net.Conn, error)) *ListenerConn {
	return &ListenerConn{
		conn:    conn,
		Control: control,
	}
}

func (l *ListenerConn) Accept() (co net.Conn, err error) {
	if l.conn == nil {
		return nil, fmt.Errorf("child listener closed")
	}
	if l.Control == nil {
		co = l.conn
		l.conn = nil
		return
	}
	co, err = l.Control(l.conn)
	l.conn = nil
	if err != nil {
		return nil, err
	}
	return co, nil
}

func (l *ListenerConn) Addr() net.Addr {
	if l.conn == nil {
		return nil
	}
	return l.conn.LocalAddr()
}

func (l *ListenerConn) Close() error {
	if l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

// PacketListenerConn is a listener that wraps a net.PacketConn and applies a control function to it.
// It is useful to apply a control function to a packet connection before it is returned to the user.
// It implements the dtlsnet.PacketListener interface.
type PacketListenerConn struct {
	*ListenerConn
}

func NewPacketListenerConn(conn net.Conn, control func(net.Conn) (net.Conn, error)) *PacketListenerConn {
	return &PacketListenerConn{
		ListenerConn: NewListenerConn(conn, control),
	}
}

func (l *PacketListenerConn) Accept() (co net.PacketConn, addr net.Addr, err error) {
	var _co net.Conn
	_co, err = l.ListenerConn.Accept()
	if err != nil {
		return nil, nil, err
	}
	return _co.(net.PacketConn), _co.RemoteAddr(), nil
}
