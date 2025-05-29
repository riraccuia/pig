package main

import (
	"crypto/tls"
	"flag"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/stun"
)

var (
	stunProto      = [2]string{"proto", "Protocol to use for STUN queries, valid values are: udp, tcp, tls"}
	stunServerAddr = [2]string{"c", "STUN host:port to query"}
	stunQry        = [2]string{"p", "Source port to query, 'R' for random port"}
)

type stunFlags struct {
	stunQry        string
	stunProto      string
	stunServerAddr string
}

func parseStunFlags() *stunFlags {
	flags := &stunFlags{}
	flagSet := flag.NewFlagSet("stun", flag.ExitOnError)
	flagSet.StringVar(&flags.stunQry, stunQry[0], "", stunQry[1])
	flagSet.StringVar(&flags.stunProto, stunProto[0], "udp", stunProto[1])
	flagSet.StringVar(&flags.stunServerAddr, stunServerAddr[0], "stun.nextcloud.com:443", stunServerAddr[1])
	flagSet.Parse(os.Args[2:])
	return flags
}

func stunMode() {
	flags := parseStunFlags()
	doStunQuery(flags)
	os.Exit(0)
}

// doStunQuery queries the STUN server to get the public IP and port
// and prints it to stdout.
func doStunQuery(flags *stunFlags) {
	var (
		logger     common.Logger = log.NewBlockingLogger()
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
