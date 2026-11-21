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

package netstack

import (
	"net/netip"
	"time"
)

const (
	defaultMTU = 1500
	// RFC 9293 §3.7.1: send MSS to assume when the peer sends no MSS option.
	defaultPeerMSS4 = 536
	defaultPeerMSS6 = 1220

	defaultBufferSize      = 2 << 20
	defaultUDPBufferSize   = 1 << 20
	defaultBacklog         = 128
	defaultQueueLen        = 256
	defaultMSL             = 15 * time.Second // RFC 9293 §3.4.2, originally 2 minutes
	defaultFinWait2Timeout = 15 * time.Second

	// RFC 6298 §2.1 and §2.4.
	initialRTO       = time.Second
	defaultMinRTO    = time.Second
	maxRTO           = 60 * time.Second
	clockGranularity = time.Millisecond

	// RFC 9293 §3.8.6.3 caps the delay at 500ms.
	delayedAckTimeout = 10 * time.Millisecond
	maxSynRetries     = 6
	maxDataRetries    = 15

	maxWindowScale = 14 // RFC 7323 §2.3
	maxWindowField = 0xffff
)

// Options tunes a Stack. The zero value selects a default for every field.
type Options struct {
	// MTU is the largest IP datagram the stack sends. It bounds UDP payloads
	// and derives the default MSS.
	MTU int
	// MSS is the local maximum segment size; zero derives it from MTU per family.
	MSS                int
	SendBufferSize     int
	RecvBufferSize     int
	DisableWindowScale bool
	// ChecksumValid verifies an inbound TCP or UDP checksum over the IP
	// pseudo-header. Nil skips validation. network.TransportChecksumValid is
	// the usual implementation when one is needed.
	ChecksumValid func(proto uint8, src, dst netip.Addr, transport []byte) bool
	// UDPRecvBufferSize bounds the bytes queued on each UDP socket; datagrams
	// arriving while it is full are dropped.
	UDPRecvBufferSize int
	Backlog           int
	// OutboundQueueLen bounds the datagrams waiting to be Read; overflow is dropped.
	OutboundQueueLen int
	MinRTO           time.Duration
	MSL              time.Duration
	// FinWait2Timeout bounds how long a closed connection waits for the peer's FIN.
	FinWait2Timeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.MTU <= 0 {
		o.MTU = defaultMTU
	}
	if o.UDPRecvBufferSize <= 0 {
		o.UDPRecvBufferSize = defaultUDPBufferSize
	}
	if o.SendBufferSize <= 0 {
		o.SendBufferSize = defaultBufferSize
	}
	if o.RecvBufferSize <= 0 {
		o.RecvBufferSize = defaultBufferSize
	}
	if o.Backlog <= 0 {
		o.Backlog = defaultBacklog
	}
	if o.OutboundQueueLen <= 0 {
		o.OutboundQueueLen = defaultQueueLen
	}
	if o.MinRTO <= 0 {
		o.MinRTO = defaultMinRTO
	}
	if o.MSL <= 0 {
		o.MSL = defaultMSL
	}
	if o.FinWait2Timeout <= 0 {
		o.FinWait2Timeout = defaultFinWait2Timeout
	}
	return o
}

// windowScaleShift returns the smallest shift that lets the receive buffer be
// advertised in the 16-bit window field.
func (o Options) windowScaleShift() uint8 {
	if o.DisableWindowScale {
		return 0
	}
	var shift uint8
	for shift < maxWindowScale && o.RecvBufferSize>>shift > maxWindowField {
		shift++
	}
	return shift
}

func (o Options) localMSS(addr netip.Addr) uint32 {
	if o.MSS > 0 {
		return uint32(o.MSS)
	}
	return uint32(o.MTU - ipHeaderLen(addr) - tcpHeaderLen)
}

// maxUDPPayload is the largest UDP payload that fits in one unfragmented datagram.
func (o Options) maxUDPPayload(addr netip.Addr) int {
	return o.MTU - ipHeaderLen(addr) - udpHeaderLen
}

func defaultPeerMSS(addr netip.Addr) uint32 {
	if addr.Is4() {
		return defaultPeerMSS4
	}
	return defaultPeerMSS6
}
