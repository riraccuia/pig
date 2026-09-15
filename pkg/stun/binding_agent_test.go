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

package stun

import (
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// mockStunServer wraps a net.Listener. For each connection returned by Accept,
// it creates a BindingAgent with the given config, attaches the conn, and
// starts Receive() to handle incoming binding requests.
type mockStunServer struct {
	listener net.Listener
	config   *BindingAgentConfig
}

func newMockStunServer(auth *IceAuth) *mockStunServer {
	config := NewControlledICEBindingAgentConfig(NoopLoggerFunc, auth, 0)
	return &mockStunServer{config: config}
}

func (s *mockStunServer) start() error {
	var err error
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			agent := NewBindingAgent(s.config)
			agent.SetConn(conn)
			agent.Receive()
		}
	}()
	return nil
}

func (s *mockStunServer) stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *mockStunServer) address() string {
	return s.listener.Addr().String()
}

func TestBindingRequestTimeout(t *testing.T) {
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

	bindReq := NewBindingAgent(NewBindingAgentConfig(NoopLoggerFunc, nil))
	bindReq.SetConn(conn)
	bindReq.Receive()

	_, err = bindReq.SendRequest(true)
	t.Logf("Error: %v", err)
	// check if err is a timeout error
	if err == nil {
		t.Error("Expected error but got none")
		return
	}

	if !os.IsTimeout(err) {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestBasicIceBindingRequest(t *testing.T) {
	// Test cases
	testCases := []struct {
		name        string
		serverAuth  *IceAuth
		clientAuth  *IceAuth
		expectError bool
	}{
		{
			name:        "Binding request without auth",
			expectError: false,
		},
		{
			name: "Binding request with ICE credentials",
			serverAuth: &IceAuth{
				LocalUfrag:     "server_frag",
				LocalPassword:  "testpass_server",
				RemoteUfrag:    "client_frag",
				RemotePassword: "testpass_client",
			},
			clientAuth: &IceAuth{
				LocalUfrag:     "client_frag",
				LocalPassword:  "testpass_client",
				RemoteUfrag:    "server_frag",
				RemotePassword: "testpass_server",
			},
			expectError: false,
		},
	}

	for _, _tc := range testCases {
		tc := _tc
		t.Run(tc.name, func(t *testing.T) {
			// Start mock STUN server
			server := newMockStunServer(tc.serverAuth)
			if err := server.start(); err != nil {
				t.Fatalf("Failed to start mock server: %v", err)
			}

			// Create connection to server
			conn, err := net.Dial("tcp", server.address())
			if err != nil {
				t.Fatalf("Failed to connect to server: %v", err)
			}

			// Create bind request
			logger := server.config.Logger
			bindReq := NewBindingAgent(NewControllingICEBindingAgentConfig(logger, tc.clientAuth, 0))
			bindReq.SetConn(conn)
			bindReq.Receive()
			// Send binding request
			result, err := bindReq.SendRequest(true)
			if err != nil {
				t.Errorf("DGB error: %v", err)
				return
			}

			server.stop()
			conn.Close()

			t.Logf("Mapped IP: %v, Mapped Port: %d", result.IP, result.Port)
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

			if result.IP == nil || result.Port == 0 {
				t.Error("Unexpected mapped IP and port")
			}
		})
	}
}

func TestIceBindingRequestAttributes(t *testing.T) {
	// Start mock STUN server
	server := newMockStunServer(nil)
	if err := server.start(); err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer server.stop()

	// Test different ICE attribute combinations
	testCases := []struct {
		name     string
		attrs    *IceConfig
		validate func(t *testing.T, ip net.IP, port int)
	}{
		{
			name: "Priority only",
			attrs: &IceConfig{
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
			attrs: &IceConfig{
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
			attrs: &IceConfig{
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
			bindReq := NewBindingAgent(NewICEBindingAgentConfig(NoopLoggerFunc, nil, tc.attrs))
			bindReq.SetConn(conn)
			bindReq.Receive()
			// Send binding request
			result, err := bindReq.SendRequest(true)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			tc.validate(t, result.IP, result.Port)
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
			Port: rand.Intn(65535-1024) + 1024,
		}
		raddr = &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: rand.Intn(65535-1024) + 1024,
		}
	)

	// Start both dialers concurrently
	wg.Add(2)
	go func() {
		defer wg.Done()
		peer1, dialErr1 = net.DialTCP("tcp", laddr, raddr)
	}()
	go func() {
		defer wg.Done()
		peer2, dialErr2 = net.DialTCP("tcp", raddr, laddr)
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
	bindReq1 := NewBindingAgent(NewICEBindingAgentConfig(NoopLoggerFunc, &IceAuth{
		LocalUfrag:     "LFRAG",
		LocalPassword:  "PASS1",
		RemoteUfrag:    "RFRAG",
		RemotePassword: "PASS2",
	}, nil))
	bindReq1.SetConn(peer1)
	bindReq1.Receive()

	bindReq2 := NewBindingAgent(NewICEBindingAgentConfig(NoopLoggerFunc, &IceAuth{
		LocalUfrag:     "RFRAG",
		LocalPassword:  "PASS2",
		RemoteUfrag:    "LFRAG",
		RemotePassword: "PASS1",
	}, nil))
	bindReq2.SetConn(peer2)
	bindReq2.Receive()

	// Send binding requests concurrently
	var (
		err1, err2       error
		result1, result2 *BindingResult
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		result1, err1 = bindReq1.SendRequest(true)
	}()

	go func() {
		defer wg.Done()
		result2, err2 = bindReq2.SendRequest(true)
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

	if result1.IP == nil {
		t.Error("Peer 1 did not receive mapped IP")
	} else {
		t.Logf("Peer 1 mapped IP: %v, port: %d", result1.IP, result1.Port)
	}

	if result2.IP == nil {
		t.Error("Peer 2 did not receive mapped IP")
	} else {
		t.Logf("Peer 2 mapped IP: %v, port: %d", result2.IP, result2.Port)
	}

	// Verify that the mapped addresses are correct
	expectedIP1 := peer1.LocalAddr().(*net.TCPAddr).IP
	expectedPort1 := peer1.LocalAddr().(*net.TCPAddr).Port
	expectedIP2 := peer2.LocalAddr().(*net.TCPAddr).IP
	expectedPort2 := peer2.LocalAddr().(*net.TCPAddr).Port

	if !result1.IP.Equal(expectedIP1) {
		t.Errorf("Peer 1 mapped IP mismatch: got %v, want %v", result1.IP, expectedIP1)
	}
	if result1.Port != expectedPort1 {
		t.Errorf("Peer 1 mapped port mismatch: got %d, want %d", result1.Port, expectedPort1)
	}

	if !result2.IP.Equal(expectedIP2) {
		t.Errorf("Peer 2 mapped IP mismatch: got %v, want %v", result2.IP, expectedIP2)
	}
	if result2.Port != expectedPort2 {
		t.Errorf("Peer 2 mapped port mismatch: got %d, want %d", result2.Port, expectedPort2)
	}
}

// TestICENominatedFlow checks that a Binding request carrying USE-CANDIDATE is handled on the
// peer connection and sets ICENominated on the receiving agent.
func TestICENominatedFlow(t *testing.T) {
	var (
		peer1, peer2       net.Conn
		dialErr1, dialErr2 error
		wg                 sync.WaitGroup
		laddr              = &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: rand.Intn(65535-1024) + 1024,
		}
		raddr = &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: rand.Intn(65535-1024) + 1024,
		}
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		peer1, dialErr1 = net.DialTCP("tcp", laddr, raddr)
	}()
	go func() {
		defer wg.Done()
		peer2, dialErr2 = net.DialTCP("tcp", raddr, laddr)
	}()
	wg.Wait()

	if dialErr1 != nil {
		t.Fatalf("failed to connect peer 1: %v", dialErr1)
	}
	if dialErr2 != nil {
		t.Fatalf("failed to connect peer 2: %v", dialErr2)
	}
	defer peer1.Close()
	defer peer2.Close()

	// Peer1 is controlling (sends nomination); peer2 is controlled and runs Receive to answer.
	agent1 := NewBindingAgent(NewControllingICEBindingAgentConfig(NoopLoggerFunc, &IceAuth{
		LocalUfrag:     "NOM_L",
		LocalPassword:  "PASS1",
		RemoteUfrag:    "NOM_R",
		RemotePassword: "PASS2",
	}, 0x7e0000ff))
	agent1.SetConn(peer1)
	agent1.Receive()

	agent2 := NewBindingAgent(NewControlledICEBindingAgentConfig(NoopLoggerFunc, &IceAuth{
		LocalUfrag:     "NOM_R",
		LocalPassword:  "PASS2",
		RemoteUfrag:    "NOM_L",
		RemotePassword: "PASS1",
	}, 0x7e0000fe))
	agent2.SetConn(peer2)
	agent2.Receive()

	// Give the receive goroutine a chance to block in Read before we send.
	time.Sleep(50 * time.Millisecond)

	result, err := agent1.ICENominateCandidate()
	if err != nil {
		t.Fatalf("ICENominateCandidate: %v", err)
	}
	if result == nil || result.IP == nil || result.Port == 0 {
		t.Fatalf("expected mapped address from nomination exchange, got %+v", result)
	}

	if !agent2.ICENominated() {
		t.Fatal("controlled peer should set ICENominated after receiving USE-CANDIDATE")
	}

	agent2.StopReceive()
}
