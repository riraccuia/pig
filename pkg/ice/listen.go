package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
)

// Listen starts a new ICE server and returns the listener.
// It returns the listener, and any error that occurs, based on the listenAddr's
// network type, it will be either a *net.UDPConn or a net.Listener.
// The listenAddr parameter is the address to listen on.
func Listen(ctx context.Context, opts *signaling.Options, listenAddr net.Addr) (listener any, err error) {
	signaler, err := signaling.NewSignaler(ctx, opts)
	if err != nil {
		return nil, err
	}

	offersChan, topicBase, err := signaler.ReceiveICEOffers(ctx, listenAddr)
	if err != nil {
		return nil, err
	}

	var (
		mappedIP   net.IP
		mappedPort int
	)

	switch listenAddr.Network() {
	case "udp":
		listener, err = net.ListenUDP("udp4", listenAddr.(*net.UDPAddr))
		if err != nil {
			break
		}
		mappedIP, mappedPort, err = stun.QueryServerUDP(opts.Logger, opts.STUNServer, listener)
	case "tcp":
		listener = conn.NewTCPListener(listenAddr.(*net.TCPAddr))
	default:
		return nil, fmt.Errorf("unsupported network type: %s", listenAddr.Network())
	}

	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case offer := <-offersChan:
				handleOffer(signaler, topicBase, offer, listenAddr, listener, mappedIP, mappedPort)
			}
			if err != nil {
				break
			}
		}
	}()

	return
}

func handleOffer(signaler *signaling.Signaler, topicBase string, offer *message.ICEMessage, listenAddr net.Addr, listener any, mappedIP net.IP, mappedPort int) (err error) {
	for _, candidate := range offer.Candidates {
		if candidate.Type != message.ICECandidateTypeSrflx {
			continue
		}
		if candidate.Protocol != listenAddr.Network() {
			continue
		}
		if candidate.Protocol == "tcp" {
			if listenAddr.(*net.TCPAddr).Port == 0 {
				// generate random port
				listenAddr = &net.TCPAddr{IP: listenAddr.(*net.TCPAddr).IP, Port: rand.Intn(65535-1024) + 1024}
			}
			mappedIP, mappedPort, err = stun.QueryServerTCP(signaler.GetOptions().Logger, signaler.GetOptions().STUNServer, listenAddr.(*net.TCPAddr).Port)
			if err != nil {
				return
			}
		}
		signaler.GetOptions().Logger.Debugf("Preparing to send ICE answer to: %s:%d", mappedIP, mappedPort)
		err = signaler.SendICEAnswer(topicBase, offer, listenAddr, mappedIP, mappedPort)
		if err != nil {
			return
		}
		switch candidate.Protocol {
		case "udp":
			_, err = conn.PunchUDP(signaler.GetOptions().Logger, listener, fmt.Sprintf("%s:%d", candidate.Address, candidate.Port))
			if err != nil {
				return
			}
		case "tcp":
			var co net.Conn
			co, err = conn.DialTCP("tcp4", listenAddr.(*net.TCPAddr), &net.TCPAddr{IP: net.ParseIP(candidate.Address).To4(), Port: candidate.Port})
			if err != nil {
				return
			}
			err = listener.(*conn.TCPListener).Load(co)
			if err != nil {
				return
			}
		}
		return
	}
	return fmt.Errorf("no valid candidate found")
}
