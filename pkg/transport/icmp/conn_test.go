package icmp

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestConnDataIntegrity writes a random payload of random size across a paired
// client/server Conn and checks the server reads it back byte-for-byte.
func TestConnDataIntegrity(t *testing.T) {
	client, server := pairedTestConns(t)
	defer client.Close()
	defer server.Close()

	// 256 KB .. 1 MB
	const minSize = 256 * 1024
	const maxSize = 1024 * 1024
	size := minSize + mrand.Intn(maxSize-minSize+1)
	want := make([]byte, size)
	if _, err := crand.Read(want); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Logf("payload size: %d", size)

	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = io.ReadAll(server)
		errCh <- err
	}()

	// Write in chunks
	const chunk = 1 << 16
	for off := 0; off < len(want); off += chunk {
		end := off + chunk
		if end > len(want) {
			end = len(want)
		}
		if _, err := client.Write(want[off:end]); err != nil {
			t.Fatalf("client write at %d: %v", off, err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	select {
	case err := <-errCh:
		// Read ends with buffer/connection closed once the peer close arrives.
		if len(got) != len(want) {
			t.Fatalf("read finished early: err=%v got=%d want=%d", err, len(got), len(want))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server read")
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("data integrity check failed: got %d bytes, want %d", len(got), len(want))
	}
}

// pairedTestConns builds a client and server Conn linked in-memory via writeHook.
func pairedTestConns(t *testing.T) (client, server *Conn) {
	t.Helper()

	clientL := newTestListener(false)
	serverL := newTestListener(true)
	t.Cleanup(func() {
		clientL.cancel()
		serverL.cancel()
	})

	const icmpID = uint16(0xC0DE)
	peerIP := &net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}

	client = newConnection(clientL, peerIP, icmpID)
	server = newConnection(serverL, peerIP, icmpID)

	clientL.writeHook = func(_ net.IP, msg *icmp.Message) error {
		return deliverTestPacket(server, msg)
	}
	serverL.writeHook = func(_ net.IP, msg *icmp.Message) error {
		return deliverTestPacket(client, msg)
	}

	return client, server
}

func newTestListener(isServer bool) *sharedListener {
	ctx, cancel := context.WithCancel(context.Background())
	mtu := 1500
	return &sharedListener{
		isServer:   isServer,
		localAddr:  &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)},
		ctx:        ctx,
		cancel:     cancel,
		mss:        mtu - ipHeaderSize - icmpHeaderSize,
		connChan:   make(chan transport.Conn, 8),
		packetChan: make(chan *Packet, 8),
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, mtu)
				return &b
			},
		},
		logger: nopLogger{},
	}
}

func deliverTestPacket(to *Conn, msg *icmp.Message) error {
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil
	}
	buf := make([]byte, len(echo.Data))
	copy(buf, echo.Data)

	p := &Packet{
		IcmpType:    msg.Type.(ipv4.ICMPType),
		IcmpCode:    uint8(msg.Code),
		IcmpEchoID:  uint16(echo.ID),
		IcmpSeq:     uint16(echo.Seq),
		IcmpPayload: buf,
		buffer:      buf,
	}
	if len(buf) >= eHeaderSize {
		p.PacketSeq, p.PacketAck = getSeqAck(buf)
		p.Data = buf[eHeaderSize:]
	}

	select {
	case to.incoming <- p:
		return nil
	case <-to.ctx.Done():
		return to.ctx.Err()
	}
}

type nopLogger struct{}

func (nopLogger) WithFields([]common.LoggerField) common.Logger {
	return nopLogger{}
}
func (nopLogger) SetLevel(string)           {}
func (nopLogger) PrintLevel(string, ...any) {}
func (nopLogger) Info(...any)               {}
func (nopLogger) Infof(string, ...any)      {}
func (nopLogger) Error(...any)              {}
func (nopLogger) Errorf(string, ...any)     {}
func (nopLogger) Debug(...any)              {}
func (nopLogger) Debugf(string, ...any)     {}
func (nopLogger) Fatal(...any)              {}
func (nopLogger) Fatalf(string, ...any)     {}
func (nopLogger) Trace(...any)              {}
func (nopLogger) Tracef(string, ...any)     {}
func (nopLogger) Flush()                    {}
