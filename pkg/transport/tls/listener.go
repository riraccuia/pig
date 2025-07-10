package tls

import (
	"crypto/tls"
	"fmt"
	"net"
)

type TLSListener struct {
	listener net.Listener
}

func NewTLSListener(listener net.Listener) *TLSListener {
	return &TLSListener{listener: listener}
}

func (t *TLSListener) Accept() (net.Conn, error) {
	conn, err := t.listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("accepted connection is not a TLS connection")
	}
	return NewTLSConn(tlsConn), nil
}

func (t *TLSListener) Close() error {
	return t.listener.Close()
}
