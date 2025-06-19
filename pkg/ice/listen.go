package ice

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

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
	var signaler *signaling.Signaler
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			signaler, err = signaling.NewSignaler(ctx, opts)
		}
		if errors.Is(err, signaling.ErrMQTTFailure) {
			if opts.Logger != nil {
				opts.Logger.Errorf("MQTT connection failed (will retry in 5 seconds): %v", err)
			}
			time.Sleep(time.Second * 5)
			continue
		}
		break
	}

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
		var (
			ok         bool
			offer      *message.ICEMessage
			offersChan <-chan *message.ICEMessage
			topicBase  string
		)
		for {
			if offersChan == nil {
				offersChan, topicBase, err = signaler.ReceiveICEOffers(ctx, listenAddr)
			}
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
				if opts.Logger != nil {
					opts.Logger.Errorf("Stopped waiting for ICE offers: %v", err)
				}
				return
			case offer, ok = <-offersChan:
				if !ok {
					offersChan = nil
					continue
				}
				handleOffer(signaler, topicBase, offer, listenAddr, listener, mappedIP, mappedPort)
			}
		}
	}()
	return
}

func handleOffer(signaler *signaling.Signaler, topicBase string, offer *message.ICEMessage, listenAddr net.Addr, listener any, mappedIP net.IP, mappedPort int) (err error) {
	logger := signaler.GetOptions().Logger

	if listenAddr.Network() == "tcp" {
		if listenAddr.(*net.TCPAddr).Port == 0 {
			// generate random port
			listenAddr = &net.TCPAddr{IP: listenAddr.(*net.TCPAddr).IP, Port: rand.Intn(65535-1024) + 1024}
		}
		mappedIP, mappedPort, err = PerformSTUNQuery(logger, signaler.GetOptions().STUNServer, listenAddr)
		if err != nil {
			logger.Errorf("Failed to query STUN server for TCP: %v", err)
			return
		}
	}
	answerCandidates, err := GetCandidates(logger, mappedIP, mappedPort, listenAddr)
	if err != nil {
		return
	}
	logger.Debugf("Preparing to send ICE answer to: %s:%d", mappedIP, mappedPort)
	err = signaler.SendICEAnswer(topicBase, offer, answerCandidates)
	if err != nil {
		return
	}
	for _, candidate := range offer.Candidates {
		logger.Debugf("Handling ICE candidate: %s | %s | %s", candidate.Type, candidate.Protocol, candidate.Address)
		if candidate.Protocol != listenAddr.Network() {
			continue
		}
		switch candidate.Protocol {
		case "udp":
			_, err = conn.PunchUDP(signaler.GetOptions().Logger, listener, fmt.Sprintf("%s:%d", candidate.Address, candidate.Port))
			if err != nil {
				return
			}
		case "tcp":
			go func() {
				var co net.Conn
				co, err = conn.DialTCP("tcp4", listenAddr.(*net.TCPAddr), &net.TCPAddr{IP: net.ParseIP(candidate.Address).To4(), Port: candidate.Port})
				if err != nil {
					return
				}
				err = listener.(*conn.TCPListener).Load(co)
				if err != nil {
					return
				}
			}()
		}
	}
	return fmt.Errorf("no valid candidate found")
}
