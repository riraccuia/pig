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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestTwoDeviceExchange(t *testing.T) {
	priv1, pub1 := mustKeyPair(t)
	priv2, pub2 := mustKeyPair(t)

	a, err := newConn(&setupOpts{
		privateKeyHex: priv1,
		peers: []peerOpts{
			{
				publicKeyHex: pub2,
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

	b, err := newConn(&setupOpts{
		privateKeyHex: priv2,
		peers: []peerOpts{
			{
				publicKeyHex: pub1,
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

	if err := a.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", pub2, portB)); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", pub1, portA)); err != nil {
		t.Fatal(err)
	}

	pktAtoB := makeIPv4Packet(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), []byte("hello-ab"))
	pktBtoA := makeIPv4Packet(net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1), []byte("hello-ba"))

	if _, err := a.Write(pktAtoB); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1500)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := b.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], pktAtoB) {
		t.Fatalf("A->B mismatch: got %v want %v", got[:n], pktAtoB)
	}

	if _, err := b.Write(pktBtoA); err != nil {
		t.Fatal(err)
	}
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = a.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], pktBtoA) {
		t.Fatalf("B->A mismatch: got %v want %v", got[:n], pktBtoA)
	}
}

func mustKeyPair(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return fmt.Sprintf("%x", priv[:]), fmt.Sprintf("%x", pub[:])
}

func makeIPv4Packet(src, dst net.IP, payload []byte) []byte {
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}
