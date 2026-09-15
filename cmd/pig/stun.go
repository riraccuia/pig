// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/controller"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/stun"
)

var (
	stunModeFlags = map[string][2]string{
		"proto": {"proto", "Protocol to use, valid options are: udp, tcp."},
		"c":     {"c", "host:port of the remote stun server to query."},
		"l":     {"l", "The local port to listen for incoming stun requests. E.g. '" + binaryName + " -stun -l 3478'."},
		"p":     {"p", "Source port to use to query a remote server, leave empty for random port."},
		"v":     {"v", "Print more verbose output, only useful with -l. Use 0 (default) for info, 1 for debug, 2 for trace."},
	}
)

type stunFlags struct {
	stunQry        string
	stunProto      string
	stunServerAddr string
	stunListenPort string
	verbose        int
}

func parseStunFlags() *stunFlags {
	flags := &stunFlags{}
	flagSet := flag.NewFlagSet("stun", flag.ExitOnError)

	flagSet.Usage = printStunUsage

	flagSet.StringVar(&flags.stunQry, stunModeFlags["p"][0], "", stunModeFlags["p"][1])
	flagSet.StringVar(&flags.stunProto, stunModeFlags["proto"][0], "udp", stunModeFlags["proto"][1])
	flagSet.StringVar(&flags.stunServerAddr, stunModeFlags["c"][0], "", stunModeFlags["c"][1])
	flagSet.StringVar(&flags.stunListenPort, stunModeFlags["l"][0], "", stunModeFlags["l"][1])
	flagSet.IntVar(&flags.verbose, stunModeFlags["v"][0], 0, stunModeFlags["v"][1])

	flagSet.Parse(os.Args[2:])

	if !isFlagPassed(flagSet, "l") && !isFlagPassed(flagSet, "c") {
		fmt.Fprintln(os.Stderr, "Either -l or -c is required")
		os.Exit(1)
	}

	return flags
}

func isFlagPassed(flagSet *flag.FlagSet, name string) bool {
	found := false
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func stunMode() {
	var (
		flags = parseStunFlags()
		ctx   = context.Background()
	)
	if flags.stunServerAddr != "" {
		doStunQuery(flags)
		os.Exit(0)
	}
	logger := log.NewLogger()
	switch flags.verbose {
	case 0:
		logger.SetLevel("info")
	case 1:
		logger.SetLevel("debug")
	case 2:
		logger.SetLevel("trace")
	}
	stunListenMode(ctx, logger, flags)
}

// doStunQuery queries the STUN server to get the public IP and port
// and prints it to stdout.
func doStunQuery(flags *stunFlags) {
	var (
		srcPort int
		err     error
	)

	if flags.stunQry == "" {
		srcPort = rand.Intn(65535-1024) + 1024
	}

	if srcPort == 0 {
		srcPort, err = strconv.Atoi(flags.stunQry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse source port: %v", err)
			os.Exit(1)
		}
	}

	tlsConfig := &tls.Config{ServerName: strings.Split(flags.stunServerAddr, ":")[0]}

	stunClient := stun.NewClient(
		flags.stunServerAddr,
	).WithDialer(
		network.NewDialer(time.Second * 5),
	)

	result, err := stunClient.QueryServer(
		flags.stunServerAddr,
		srcPort,
		flags.stunProto,
		tlsConfig,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Server:\t%s\n", flags.stunServerAddr)
	fmt.Fprintf(w, "Address:\t%s\n", result.ServerAddr)
	fmt.Fprintf(w, "Local address:\t:%d\n", srcPort)
	fmt.Fprintf(w, "Mapped address:\t%s:%d\n", result.IP, result.Port)
	w.Flush()

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
		listenAddr, err = net.ResolveUDPAddr("udp", ":"+flags.stunListenPort)
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to resolve STUN listen address: %v", err)
		}
	case "tcp":
		listenAddr, err = net.ResolveTCPAddr("tcp", flags.stunListenPort)
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to resolve STUN listen address: %v", err)
		}
	default:
		log.NewBlockingLogger().Fatalf("Unimplemented STUN protocol for listen: %s", flags.stunProto)
	}

	serverConfig := &stun.ServerConfig{
		Logger: func(level string, args ...any) {
			logger.PrintLevel(level, args...)
		},
		TLSConfig:     nil,
		UDPListenFunc: network.ListenUDP,
		TCPListenFunc: nil,
	}

	ctrl := controller.New(ctx).WithLogger(logger)

	ctrl.StartCallback(func(ctx context.Context) {
		s, err := stun.NewServer(serverConfig)
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to create STUN server: %v", err)
		}
		err = s.Listen(ctx, listenAddr)
		if err != nil {
			log.NewBlockingLogger().Fatalf("Failed to listen on STUN server: %v", err)
		}
	})

	ctrl.HandleGracefulShutdown(nil)
}
