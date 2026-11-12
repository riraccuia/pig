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

package wireguard

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestIdleWatcherKeepaliveKeepsAlive(t *testing.T) {
	a, b, pubA := linkedPeers(t, 1)
	b.startIdleWatcherWithThreshold(pubA, 2*time.Second)

	// Trigger handshake so keepalives can start.
	pkt := makeIPv4Packet(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), []byte("ping"))
	if _, err := a.Write(pkt); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1500)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := b.Read(got); err != nil {
		t.Fatal(err)
	}

	// Quiet longer than watch threshold; A's keepalives should refresh B's rx_bytes.
	time.Sleep(5 * time.Second)

	select {
	case <-b.tun.closed:
		t.Fatal("receiver closed despite peer keepalives")
	default:
	}
}

func TestIdleWatcherClosesWhenPeerGone(t *testing.T) {
	a, b, pubA := linkedPeers(t, 1)
	b.startIdleWatcherWithThreshold(pubA, 2*time.Second)

	pkt := makeIPv4Packet(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), []byte("ping"))
	if _, err := a.Write(pkt); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1500)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := b.Read(got); err != nil {
		t.Fatal(err)
	}

	// Stop keepalives from A.
	_ = a.Close()

	select {
	case <-b.tun.closed:
	case <-time.After(6 * time.Second):
		t.Fatal("receiver did not close after peer went away")
	}
}

func TestPeerRxBytesParse(t *testing.T) {
	const peer = "aabbccdd"
	ipc := "private_key=00\npublic_key=" + peer + "\nrx_bytes=42\ntx_bytes=1\n"
	n, ok := peerRxBytes(ipc, peer)
	if !ok || n != 42 {
		t.Fatalf("got %d %v want 42 true", n, ok)
	}
	if _, ok := peerRxBytes(ipc, "nope"); ok {
		t.Fatal("expected miss for unknown peer")
	}
}

// linkedPeers returns A (with keepalive), B (listen-style, no watcher yet), and A's public key hex.
func linkedPeers(t *testing.T, keepaliveSeconds int) (a, b *Conn, pubA string) {
	t.Helper()
	priv1, pub1 := mustKeyPair(t)
	priv2, pub2 := mustKeyPair(t)

	var err error
	a, err = newConn(&setupOpts{
		privateKeyHex: priv1,
		peers: []peerOpts{
			{
				publicKeyHex: pub2,
				allowedIPs:   append([]string(nil), DefaultWGAllowedIPs...),
			},
		},
		listenPort: 0,
		mtu:        1420,
		localAddr:  &net.UDPAddr{},
		remoteAddr: &net.UDPAddr{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	b, err = newConn(&setupOpts{
		privateKeyHex: priv2,
		peers: []peerOpts{
			{
				publicKeyHex: pub1,
				allowedIPs:   append([]string(nil), DefaultWGAllowedIPs...),
			},
		},
		listenPort: 0,
		mtu:        1420,
		localAddr:  &net.UDPAddr{},
		remoteAddr: &net.UDPAddr{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	portA, err := listenPortFromIpc(a.dev)
	if err != nil {
		t.Fatal(err)
	}
	portB, err := listenPortFromIpc(b.dev)
	if err != nil {
		t.Fatal(err)
	}
	// Set endpoints first, then enable keepalive so the initial PKA does not race before endpoint exists.
	if err := a.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=%d\n", pub2, portB, keepaliveSeconds)); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", pub1, portA)); err != nil {
		t.Fatal(err)
	}
	return a, b, pub1
}
