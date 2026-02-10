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
		Mode: config.ModeServer,
		TunnelConfig: config.TunnelConfig{
			TLSConfig: config.TLSConfig{
				Insecure: true,
				CertFile: certPath,
				KeyFile:  keyPath,
			},
			TunnelAddress: "10.0.0.1/24",
			MTU:           1300,
			StreamCount:   4,
			Target: config.Target{
				Address: "127.0.0.1",
				Port:    12345,
			},
		},
	}

	// Create client config
	clientConfig := &config.Config{
		Mode: config.ModeClient,
		TunnelConfig: config.TunnelConfig{
			TLSConfig: config.TLSConfig{
				Insecure: true,
			},
			TunnelAddress: "10.0.0.2/32",
			MTU:           1300,
			// CertFile:    certPath,
			StreamCount: 4,
			Target: config.Target{
				Address: "127.0.0.1",
				Port:    12345,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewLogger()
	logger.SetLevel("debug")

	// Create and start client with mock adapter
	cli, err := client.New(logger, &clientConfig.TunnelConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create and start server with mock adapter
	srv, err := server.New(logger, &serverConfig.TunnelConfig, nil)
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
