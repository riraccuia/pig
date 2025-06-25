package stun

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/log"
)

// mockStunServer implements a simple STUN server for testing
type mockStunServer struct {
	t        *testing.T
	listener net.Listener
	auth     *StunAuthConfig
	iceAttrs *IceAttributes
	done     chan struct{}
}

func newMockStunServer(t *testing.T, auth *StunAuthConfig) *mockStunServer {
	return &mockStunServer{
		t:    t,
		auth: auth,
		iceAttrs: &IceAttributes{
			Priority:      0x6E0001FF,
			UseCandidate:  false,
			IceControlled: 0x12345678,
		},
		done: make(chan struct{}),
	}
}

func (s *mockStunServer) start() error {
	var err error
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	go s.serve()
	return nil
}

func (s *mockStunServer) stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	close(s.done)
}

func (s *mockStunServer) serve() {
	for {
		select {
		case <-s.done:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					s.t.Logf("Accept error: %v", err)
				}
				continue
			}

			go s.handleConnection(conn)
		}
	}
}

func (s *mockStunServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Create bind request handler
	bindReq := NewIceBindRequest(log.NewBlockingLogger())
	if s.auth != nil {
		// For ICE, username should be "peer_frag:local_frag"
		// The server's username fragment is s.auth.Username
		// The client's username fragment will be in the request
		bindReq.Auth = s.auth
	}
	bindReq.Ice = s.iceAttrs
	s.t.Logf("Sending SendUsername: %s, controlling: %d, controlled: %d", bindReq.Auth.SendUsername, bindReq.Ice.IceControlling, bindReq.Ice.IceControlled)
	mappedIP, mappedPort, err := bindReq.SendBindingRequest(conn)
	if err != nil {
		s.t.Logf("Send binding request error: %v", err)
		return
	}
	s.t.Logf("Mapped IP: %v, Mapped Port: %d", mappedIP, mappedPort)
}

func (s *mockStunServer) address() string {
	return s.listener.Addr().String()
}

func TestIceBindingRequest(t *testing.T) {
	// Test cases
	testCases := []struct {
		name        string
		serverAuth  *StunAuthConfig
		clientAuth  *StunAuthConfig
		iceAttrs    *IceAttributes
		expectError bool
	}{
		/*{
			name: "Basic binding request without auth",
			iceAttrs: &IceAttributes{
				Priority:       0x6E0001FF,
				UseCandidate:   true,
				IceControlling: 0x12345678,
			},
			expectError: false,
		},*/
		{
			name: "Binding request with ICE credentials",
			serverAuth: &StunAuthConfig{
				SendUsername: "client_frag:server_frag",
				Username:     "server_frag",
				Password:     "testpass",
			},
			clientAuth: &StunAuthConfig{
				SendUsername: "server_frag:client_frag",
				Username:     "client_frag",
				Password:     "testpass",
			},
			iceAttrs: &IceAttributes{
				Priority:       0x6E0001FF,
				UseCandidate:   true,
				IceControlling: 0x12345678,
			},
			expectError: false,
		},
		/*{
			name: "Binding request with invalid peer fragment",
			serverAuth: &StunAuthConfig{
				Username: "server_frag",
				Password: "testpass",
			},
			clientAuth: &StunAuthConfig{
				SendUsername: "wrong_peer:client_frag",
				Username:     "client_frag",
				Password:     "testpass",
			},
			iceAttrs: &IceAttributes{
				Priority:       0x6E0001FF,
				UseCandidate:   true,
				IceControlling: 0x12345678,
			},
			expectError: true,
		},
		{
			name: "Binding request with invalid message integrity",
			serverAuth: &StunAuthConfig{
				Username: "server_frag",
				Password: "testpass",
			},
			clientAuth: &StunAuthConfig{
				SendUsername: "server_frag:client_frag",
				Username:     "client_frag",
				Password:     "wrongpass",
			},
			iceAttrs: &IceAttributes{
				Priority:       0x6E0001FF,
				UseCandidate:   true,
				IceControlling: 0x12345678,
			},
			expectError: true,
		},*/
	}

	for _, _tc := range testCases {
		tc := _tc
		t.Run(tc.name, func(t *testing.T) {
			// Start mock STUN server
			server := newMockStunServer(t, tc.serverAuth)
			if err := server.start(); err != nil {
				t.Fatalf("Failed to start mock server: %v", err)
			}

			// Create connection to server
			conn, err := net.Dial("tcp", server.address())
			if err != nil {
				t.Fatalf("Failed to connect to server: %v", err)
			}

			// Create bind request
			logger := log.NewBlockingLogger()
			logger.SetLevel("debug")
			bindReq := NewIceBindRequest(logger)
			if tc.clientAuth != nil {
				bindReq.Auth = tc.clientAuth
			}
			bindReq.Ice = tc.iceAttrs

			// Send binding request
			mappedIP, mappedPort, err := bindReq.SendBindingRequest(conn)

			server.stop()
			conn.Close()

			t.Logf("Mapped IP: %v, Mapped Port: %d", mappedIP, mappedPort)
			t.Logf("Error: %v", err)

			// Check results
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
				return
			}

			if tc.expectError {
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if mappedIP == nil || mappedPort == 0 {
				t.Error("Unexpected mapped IP and port")
			}
		})
	}
}

func TestIceBindingRequestTimeout(t *testing.T) {
	// Create a temporary listener
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create temporary listener: %v", err)
	}
	addr := listener.Addr().String()

	go func() {
		// the listener accepts a connection but does not read it
		listener.Accept()
	}()

	// Connect to the listener
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	bindReq := NewIceBindRequest(log.NewBlockingLogger())
	bindReq.Ice = &IceAttributes{
		Priority:       0x6E0001FF,
		UseCandidate:   true,
		IceControlling: 0x12345678,
	}

	_, _, err = bindReq.SendBindingRequest(conn)
	t.Logf("Error: %v", err)
	// check if err is a timeout error
	if err == nil {
		t.Error("Expected error but got none")
		return
	}

	err = errors.Unwrap(err)

	if !os.IsTimeout(err) {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestIceBindingRequestAttributes(t *testing.T) {
	// Start mock STUN server
	server := newMockStunServer(t, nil)
	if err := server.start(); err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer server.stop()

	// Test different ICE attribute combinations
	testCases := []struct {
		name     string
		attrs    *IceAttributes
		validate func(t *testing.T, ip net.IP, port int)
	}{
		{
			name: "Priority only",
			attrs: &IceAttributes{
				Priority: 0x6E0001FF,
			},
			validate: func(t *testing.T, ip net.IP, port int) {
				if ip == nil || port == 0 {
					t.Error("Expected valid mapped address")
				}
			},
		},
		{
			name: "UseCandidate only",
			attrs: &IceAttributes{
				UseCandidate: true,
			},
			validate: func(t *testing.T, ip net.IP, port int) {
				if ip == nil || port == 0 {
					t.Error("Expected valid mapped address")
				}
			},
		},
		{
			name: "All attributes",
			attrs: &IceAttributes{
				Priority:       0x6E0001FF,
				UseCandidate:   true,
				IceControlling: 0x12345678,
				IceControlled:  0x87654321,
			},
			validate: func(t *testing.T, ip net.IP, port int) {
				if ip == nil || port == 0 {
					t.Error("Expected valid mapped address")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create connection to server
			conn, err := net.Dial("tcp", server.address())
			if err != nil {
				t.Fatalf("Failed to connect to server: %v", err)
			}
			defer conn.Close()

			// Create bind request
			bindReq := NewIceBindRequest(log.NewBlockingLogger())
			bindReq.Ice = tc.attrs

			// Send binding request
			ip, port, err := bindReq.SendBindingRequest(conn)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			tc.validate(t, ip, port)
		})
	}
}

func TestConcurrentBindingRequests(t *testing.T) {
	// Create two peers that will dial each other concurrently
	var (
		peer1, peer2       net.Conn
		dialErr1, dialErr2 error
		wg                 sync.WaitGroup
		laddr              = &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 7000,
		}
		raddr = &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 7001,
		}
	)

	// Start both dialers concurrently
	wg.Add(2)
	go func() {
		defer wg.Done()
		peer1, dialErr1 = conn.DialTCP("tcp", laddr, raddr)
	}()
	go func() {
		defer wg.Done()
		peer2, dialErr2 = conn.DialTCP("tcp", raddr, laddr)
	}()

	// Wait for both dialers to complete
	wg.Wait()

	// Check for dial errors
	if dialErr1 != nil {
		t.Fatalf("Failed to connect peer 1: %v", dialErr1)
	}
	if dialErr2 != nil {
		t.Fatalf("Failed to connect peer 2: %v", dialErr2)
	}
	defer peer1.Close()
	defer peer2.Close()

	// Create bind requests
	bindReq1 := NewIceBindRequest(log.NewBlockingLogger())
	bindReq1.SetAuthConfig("LFRAG", "RFRAG", "PASS", "test", "nonce1")

	bindReq2 := NewIceBindRequest(log.NewBlockingLogger())
	bindReq2.SetAuthConfig("RFRAG", "LFRAG", "PASS", "test", "nonce2")

	// Send binding requests concurrently
	var (
		err1, err2   error
		ip1, ip2     net.IP
		port1, port2 int
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		ip1, port1, err1 = bindReq1.SendBindingRequest(peer1)
	}()

	go func() {
		defer wg.Done()
		ip2, port2, err2 = bindReq2.SendBindingRequest(peer2)
	}()

	// Wait for both requests to complete
	wg.Wait()

	// Check results
	if err1 != nil {
		t.Errorf("Peer 1 binding request failed: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Peer 2 binding request failed: %v", err2)
	}

	if ip1 == nil {
		t.Error("Peer 1 did not receive mapped IP")
	} else {
		t.Logf("Peer 1 mapped IP: %v, port: %d", ip1, port1)
	}

	if ip2 == nil {
		t.Error("Peer 2 did not receive mapped IP")
	} else {
		t.Logf("Peer 2 mapped IP: %v, port: %d", ip2, port2)
	}

	// Verify that the mapped addresses are correct
	expectedIP1 := peer1.LocalAddr().(*net.TCPAddr).IP
	expectedPort1 := peer1.LocalAddr().(*net.TCPAddr).Port
	expectedIP2 := peer2.LocalAddr().(*net.TCPAddr).IP
	expectedPort2 := peer2.LocalAddr().(*net.TCPAddr).Port

	if !ip1.Equal(expectedIP1) {
		t.Errorf("Peer 1 mapped IP mismatch: got %v, want %v", ip1, expectedIP1)
	}
	if port1 != expectedPort1 {
		t.Errorf("Peer 1 mapped port mismatch: got %d, want %d", port1, expectedPort1)
	}

	if !ip2.Equal(expectedIP2) {
		t.Errorf("Peer 2 mapped IP mismatch: got %v, want %v", ip2, expectedIP2)
	}
	if port2 != expectedPort2 {
		t.Errorf("Peer 2 mapped port mismatch: got %d, want %d", port2, expectedPort2)
	}
}
