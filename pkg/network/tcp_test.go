package network

import (
	"log"
	"math/rand"
	"net"
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
