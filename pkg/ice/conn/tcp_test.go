package conn

import (
	"crypto/tls"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestReusePort(t *testing.T) {
	conn, err := DialTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 12345,
	}, &net.TCPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 53,
	})
	if err != nil {
		t.Fatalf("Failed to create socket: %v", err)
	}
	conn.Close()

	conn, err = DialTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 12345,
	}, &net.TCPAddr{
		IP:   net.ParseIP("8.8.8.8"),
		Port: 53,
	})
	if err != nil {
		t.Fatalf("Failed to create socket2: %v", err)
	}
	conn.Close()
}

func TestCreateSocket(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	randPort := rand.Intn(65535-1024) + 1024
	randPort2 := rand.Intn(65535-1024) + 1024

	go func() {
		conn2, err := DialTCP("tcp", &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort,
		}, &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort2,
		})
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		buf := make([]byte, 1024)
		n, err := conn2.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read from socket: %v", err)
		}
		t.Logf("Received message: %s", buf[:n])
		wg.Done()
	}()

	go func() {
		conn, err := DialTCP("tcp", &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort2,
		}, &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort,
		})
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))

		_, err = conn.Write([]byte("Hello from client"))
		if err != nil {
			log.Fatalf("Failed to write to socket: %v", err)
		}

		wg.Done()
	}()

	wg.Wait()
}

func TestCreateConn(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)

	randPort := rand.Intn(65535-1024) + 1024
	randPort2 := rand.Intn(65535-1024) + 1024

	go func() {
		conn2, err := net.DialTCP("tcp", &net.TCPAddr{
			Port: randPort,
		}, &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort2,
		})
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		buf := make([]byte, 1024)
		n, err := conn2.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read from socket: %v", err)
		}
		t.Logf("Received message: %s", buf[:n])
		wg.Done()
	}()

	go func() {
		conn, err := net.DialTCP("tcp", &net.TCPAddr{
			Port: randPort2,
		}, &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: randPort,
		})
		if err != nil {
			log.Fatalf("Failed to create socket: %v", err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))

		_, err = conn.Write([]byte("Hello from client"))
		if err != nil {
			log.Fatalf("Failed to write to socket: %v", err)
		}

		wg.Done()
	}()

	wg.Wait()

}

func TestCreateTCPSocket2HTTPS(t *testing.T) {
	// Use a random source port
	sourcePort := rand.Intn(65535-1024) + 1024

	// resolve example.com's IP
	ips, err := net.LookupIP("example.com")
	if err != nil {
		t.Fatalf("Failed to resolve example.com: %v", err)
	}

	// Connect to example.com on port 443 (HTTPS)
	conn, err := DialTCP("tcp", &net.TCPAddr{
		Port: sourcePort,
	}, &net.TCPAddr{
		IP:   ips[0],
		Port: 443,
	})
	if err != nil {
		t.Fatalf("Failed to create socket: %v", err)
	}
	defer conn.Close()

	// Set a deadline for the entire operation
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Create TLS connection
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	// Create custom transport that uses our connection
	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		// Disable connection pooling since we're using a single connection
		DisableKeepAlives: true,
		// Disable compression since we're testing basic connectivity
		DisableCompression: true,
	}

	// Create HTTP client with our custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Make the request
	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	// Verify we got a successful response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify we got some content
	if len(body) == 0 {
		t.Error("Expected non-empty response body")
	}

	t.Logf("Successfully received response with status %d and body length %d",
		resp.StatusCode, len(body))
}
