package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/packet"
	"github.com/riraccuia/pig/pkg/server"
	"github.com/riraccuia/pig/pkg/transport"
	qt "github.com/riraccuia/pig/pkg/transport/quic"
	"golang.org/x/net/quic"
)

// MockTunnelAdapter implements adapter.TunnelAdapter interface for testing
type MockTunnelAdapter struct {
	cloneChan chan []byte
	writeChan chan []byte
	ip        net.IP
	closed    bool
	mu        sync.Mutex
}

func NewMockTunnelAdapter(ip net.IP) *MockTunnelAdapter {
	return &MockTunnelAdapter{
		cloneChan: make(chan []byte, 100),
		writeChan: make(chan []byte, 100),
		ip:        ip,
	}
}

func (m *MockTunnelAdapter) Read(b []byte) (int, error) {
	data := <-m.writeChan
	copy(b, data)
	return len(data), nil
}

func (m *MockTunnelAdapter) ReadClone(b []byte) (int, error) {
	data := <-m.cloneChan
	copy(b, data)
	return len(data), nil
}

func (m *MockTunnelAdapter) Write(b []byte) (int, error) {
	data := make([]byte, len(b))
	copy(data, b)
	m.writeChan <- data
	m.cloneChan <- data
	return len(b), nil
}

func (m *MockTunnelAdapter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *MockTunnelAdapter) IP() net.IP {
	return m.ip
}

func (m *MockTunnelAdapter) Name() string {
	return "mock"
}

func (m *MockTunnelAdapter) Index() int {
	return 0
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) (certPath string, keyPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	certPath = filepath.Join(tmpDir, "test.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatal(err)
	}

	keyPath = filepath.Join(tmpDir, "test.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func TestQUICConn(t *testing.T) {
	// Generate test certificate
	certPath, keyPath := generateTestCertificate(t)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
		NextProtos: []string{"quic-tunnel"},
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Errorf("failed to load TLS certificate: %v", err)
		return
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	endpoint, err := quic.Listen(
		"udp",
		fmt.Sprintf(":%d", 1234),
		&quic.Config{
			TLSConfig: tlsConfig,
		},
	)

	go func() {
		conn, err := endpoint.Accept(context.Background())
		if err != nil {
			return
		}
		t.Logf("New connection")
		str, err := conn.NewStream(context.Background())
		if err != nil {
			t.Errorf("failed to create stream: %v", err)
		}
		t.Logf("Stream created %p\n", str)
		str.Flush()
		_, err = str.Read(make([]byte, 1024))
		if err != nil {
			t.Logf("Failed to read from stream: %v", err)
		}
		t.Logf("Read data from stream")
	}()

	time.Sleep(time.Second)

	t.Logf("Dialing")

	tlsConfig2 := tlsConfig.Clone()
	tlsConfig2.Certificates = nil

	clientEndpoint, err := quic.Listen(
		"udp",
		fmt.Sprintf(":%d", 0),
		&quic.Config{
			TLSConfig: tlsConfig2,
		},
	)
	if err != nil {
		t.Errorf("failed to create QUIC listener: %v", err)
	}
	conn, err := clientEndpoint.Dial(context.Background(), "udp", "127.0.0.1:1234", &quic.Config{TLSConfig: tlsConfig})
	if err != nil {
		t.Errorf("failed to establish QUIC connection: %v", err)
	}
	t.Logf("Client connected")
	str, err := conn.AcceptStream(context.Background())
	if err != nil {
		t.Errorf("failed to accept stream: %v", err)
	}
	t.Logf("Stream accepted %p\n", str)
	// str.Flush()
	str.Write([]byte("Hello, world!"))
	str.Flush()
	time.Sleep(time.Second)
}

func TestEndToEndTunnelWithQUICMockedAdapter(t *testing.T) {
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
			TunnelAddress: "10.0.0.1/32",
			MTU:           1300,
			StreamCount:   4,
			Target: config.Target{
				Address: "127.0.0.1",
				Port:    12345,
			},
		},
	}

	// Create mock adapters
	serverAdapter := NewMockTunnelAdapter(net.ParseIP("10.0.0.1"))
	clientAdapter := NewMockTunnelAdapter(net.ParseIP("10.0.0.2"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.NewLogger()
	logger.SetLevel("debug")

	// Create and start client with mock adapter
	cli, err := client.NewWithAdapter(logger, &clientConfig.TunnelConfig, clientAdapter, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create and start server with mock adapter
	srv, err := server.NewWithAdapter(logger, &serverConfig.TunnelConfig, serverAdapter, nil)
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

	// Wait for connection to establish
	time.Sleep(time.Second)

	// Create a test IPv4 packet
	testPacket := make([]byte, 40)                 // Minimum IPv4 header size
	testPacket[0] = 0x45                           // Version 4, Header length 5 (20 bytes)
	binary.BigEndian.PutUint16(testPacket[2:], 40) // Total length
	packet.IPv4Packet(testPacket).SetSourceIP(net.ParseIP("10.0.0.2"))
	packet.IPv4Packet(testPacket).SetDestinationIP(net.ParseIP("10.0.0.1"))
	rand.Read(testPacket[20:])

	t.Logf("Sending packet: %x", testPacket)

	// Write packet to client adapter
	if _, err := clientAdapter.Write(testPacket); err != nil {
		t.Fatalf("Failed to write packet to client adapter: %v", err)
	}
	t.Logf("Wrote packet to client adapter")

	time.Sleep(time.Second)
	// Read packet from server adapter
	receivedPacket := make([]byte, 1500)
	n, err := serverAdapter.ReadClone(receivedPacket)
	if err != nil {
		t.Fatalf("Failed to read packet from server adapter: %v", err)
	}
	t.Logf("Read packet from server adapter")
	receivedPacket = receivedPacket[20:n]
	t.Logf("Received packet: %x", receivedPacket)

	// Compare original and received packets
	if !bytes.Equal(testPacket[20:40], receivedPacket) {
		t.Errorf("Received packet does not match sent packet.\nSent: %x\nReceived: %x",
			testPacket[20:40], receivedPacket)
	}
}

func getClientQUICDialFunc(ctx context.Context, config *config.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		tlsConfig, err := createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		endpoint, err := quic.Listen("udp", ":0", &quic.Config{TLSConfig: tlsConfig})
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		conn, err := endpoint.Dial(ctx, "udp", fmt.Sprintf("%s:%d", config.TunnelConfig.Target.Address, config.TunnelConfig.Target.Port), &quic.Config{TLSConfig: tlsConfig})
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return qt.NewQuicConn(conn), nil
	}
}

func getServerQUICListenFunc(ctx context.Context, config *config.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		tlsConfig, err := createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		endpoint, err := quic.Listen(
			"udp",
			fmt.Sprintf(":%d", config.TunnelConfig.Target.Port),
			&quic.Config{TLSConfig: tlsConfig},
		)

		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		return qt.NewQuicTransport(ctx, endpoint), nil
	}
}

func createTLSConfig(cfg *config.Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TunnelConfig.TLSConfig.Insecure,
		MinVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
	}

	if cfg.TunnelConfig.TLSConfig.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TunnelConfig.TLSConfig.CertFile, cfg.TunnelConfig.TLSConfig.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
