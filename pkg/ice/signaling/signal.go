package signaling

import (
	"context"
	"net"
)

func SignalPunchRequest(ctx context.Context, opts *Options, targetAddress string, udpConn *net.UDPConn) (err error) {
	sc, err := NewClient(opts, targetAddress)
	if err != nil {
		return err
	}
	return sc.PublishICEOffer(ctx, udpConn)
}

func ReceivePunchRequests(ctx context.Context, opts *Options, udpConn *net.UDPConn) (err error) {
	ss, err := NewServer(opts, udpConn)
	if err != nil {
		return err
	}
	return ss.Start(ctx)
}
