package tests

import (
	"context"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/server"
)

func TestEndToEndTunnelWithQUIC(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := generateTestCertificate(t)

	// Create server config
	serverConfig := &config.Config{
		Insecure:      true,
		Mode:          "server",
		TunnelAddress: "10.0.0.1/24",
		MTU:           1300,
		CertFile:      certPath,
		KeyFile:       keyPath,
		StreamCount:   4,
		Target: config.Target{
			Address: "127.0.0.1",
			Port:    12345,
		},
	}

	// Create client config
	clientConfig := &config.Config{
		Insecure:      true,
		Mode:          "client",
		TunnelAddress: "10.0.0.2/32",
		MTU:           1300,
		// CertFile:    certPath,
		StreamCount: 4,
		Target: config.Target{
			Address: "127.0.0.1",
			Port:    12345,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewLogger(ctx)
	logger.SetLevel("debug")

	// Create and start client with mock adapter
	cli, err := client.New(logger, clientConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create and start server with mock adapter
	srv, err := server.New(logger, serverConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(ctx, getServerQUICListenFunc(ctx, serverConfig)); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	if err := cli.Start(ctx, getClientQUICDialFunc(ctx, clientConfig)); err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}
	// defer cli.Close()

	time.Sleep(300 * time.Second)
}
