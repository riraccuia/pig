package main

import (
	"context"
	"crypto/tls"
	"flag"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/controller"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/stun"
)

var (
	stunProto      = [2]string{"proto", "Protocol to use for STUN queries, valid values are: udp, tcp, tls"}
	stunServerAddr = [2]string{"c", "STUN host:port to query"}
	stunListenAddr = [2]string{"l", "STUN host:port to listen on (default operating when no flags are provided)"}
	stunQry        = [2]string{"p", "Source port to query, 'R' for random port"}
)

type stunFlags struct {
	stunQry        string
	stunProto      string
	stunServerAddr string
	stunListenAddr string
}

func parseStunFlags() *stunFlags {
	flags := &stunFlags{}
	flagSet := flag.NewFlagSet("stun", flag.ExitOnError)
	flagSet.StringVar(&flags.stunQry, stunQry[0], "", stunQry[1])
	flagSet.StringVar(&flags.stunProto, stunProto[0], "udp", stunProto[1])
	flagSet.StringVar(&flags.stunServerAddr, stunServerAddr[0], "stun.nextcloud.com:443", stunServerAddr[1])
	flagSet.StringVar(&flags.stunListenAddr, stunListenAddr[0], ":3478", stunListenAddr[1])
	flagSet.Parse(os.Args[2:])
	return flags
}

func stunMode() {
	var (
		flags                = parseStunFlags()
		logger common.Logger = log.NewBlockingLogger()
		ctx                  = context.Background()
	)
	if flags.stunQry != "" {
		doStunQuery(logger, flags)
		os.Exit(0)
	}
	if flags.stunListenAddr == "" {
		logger.Fatalf("Either -l or -p is required")
		os.Exit(1)
	}
	stunListenMode(ctx, logger, flags)
}

// doStunQuery queries the STUN server to get the public IP and port
// and prints it to stdout.
func doStunQuery(logger common.Logger, flags *stunFlags) {
	var (
		srcPort    int
		mappedIP   net.IP
		mappedPort int
		err        error
	)

	if flags.stunQry == "" {
		return
	}

	if flags.stunQry == "R" {
		srcPort = rand.Intn(65535-1024) + 1024
		logger.Infof("STUN: Using random source port: %d", srcPort)
	}

	if srcPort == 0 {
		srcPort, err = strconv.Atoi(flags.stunQry)
		if err != nil {
			logger.Fatalf("Failed to parse source port: %v", err)
		}
	}

	mappedIP, mappedPort, err = stun.QueryServer(
		logger,
		flags.stunServerAddr,
		srcPort,
		flags.stunProto,
		&tls.Config{ServerName: strings.Split(flags.stunServerAddr, ":")[0]},
	)
	if err != nil {
		logger.Fatalf("Failed to query STUN server: %v", err)
	}

	logger.Infof("STUN server returned mapped <ip:port>: %s:%d", mappedIP, mappedPort)

	os.Exit(0)
}

// stunListenMode listens for STUN requests on the specified protocol, address and port.
func stunListenMode(ctx context.Context, logger common.Logger, flags *stunFlags) {
	var (
		listenAddr net.Addr
		err        error
	)
	switch flags.stunProto {
	case "udp":
		listenAddr, err = net.ResolveUDPAddr("udp", flags.stunListenAddr)
		if err != nil {
			logger.Fatalf("Failed to resolve STUN listen address: %v", err)
		}
	case "tcp":
		listenAddr, err = net.ResolveTCPAddr("tcp", flags.stunListenAddr)
		if err != nil {
			logger.Fatalf("Failed to resolve STUN listen address: %v", err)
		}
	default:
		logger.Fatalf("Unimplemented STUN protocol for listen: %s", flags.stunProto)
	}
	ctrl := controller.New(ctx).WithLogger(logger)

	ctrl.StartCallback(func(ctx context.Context) {
		_, err := stun.NewServerWithContext(ctx, logger, listenAddr)
		if err != nil {
			logger.Fatalf("Failed to create STUN server: %v", err)
		}
	})

	ctrl.HandleGracefulShutdown(nil)
}
