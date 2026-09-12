//go:build manual

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/adapter"
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
		Tunnels: []config.TunnelConfig{
			{
				Direction: config.TunnelDirectionListen,
				Adapter: &config.AdapterConfig{
					TunnelAddress: []string{"10.0.0.1/24"},
					MTU:           1300,
				},
				TLSConfig: config.TLSConfig{
					Insecure: true,
					CertFile: certPath,
					KeyFile:  keyPath,
				},
				StreamCount: 4,
				Listen: config.ListenTarget{
					Address: "127.0.0.1",
					Port:    12345,
				},
			},
		},
	}

	// Create client config
	clientConfig := &config.Config{
		Adapter: config.AdapterConfig{
			TunnelAddress: []string{"10.0.0.2/32"},
			MTU:           1300,
		},
		Tunnels: []config.TunnelConfig{
			{
				Direction: config.TunnelDirectionConnect,
				TLSConfig: config.TLSConfig{
					Insecure: true,
				},
				StreamCount: 4,
				Connect: config.ConnectTarget{
					Address: "127.0.0.1",
					Port:    12345,
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewLogger()
	logger.SetLevel("debug")

	// Create and start client
	clientAdapter, err := adapter.NewAdapter(adapter.AdapterConfig{
		Address: clientConfig.Adapter.TunnelAddress,
		MTU:     clientConfig.Adapter.MTU,
	})
	if err != nil {
		t.Fatalf("Failed to create client adapter: %v", err)
	}
	cli, err := client.NewWithAdapter(logger, &clientConfig.Adapter, &clientConfig.Tunnels[0], clientAdapter, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create and start server
	serverAdapter, err := adapter.NewAdapter(adapter.AdapterConfig{
		Address: serverConfig.Tunnels[0].Adapter.TunnelAddress,
		MTU:     serverConfig.Tunnels[0].Adapter.MTU,
	})
	if err != nil {
		t.Fatalf("Failed to create server adapter: %v", err)
	}
	srv, err := server.NewWithAdapter(logger, serverConfig.Tunnels[0].Adapter, &serverConfig.Tunnels[0], serverAdapter, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(ctx, getServerQUICListenFunc(serverConfig)); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	if err := cli.Start(ctx, getClientQUICDialFunc(clientConfig)); err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}
	// defer cli.Close()

	time.Sleep(300 * time.Second)
}
