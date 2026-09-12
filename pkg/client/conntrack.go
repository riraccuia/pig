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

package client

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash"
	"github.com/riraccuia/pig/pkg/network"
)

type protocolData interface {
	Bytes() []byte
	Inverted() protocolData
	ExpireDuration() time.Duration
}

type Tuple struct {
	Family       byte
	SrcIP        net.IP
	DestIP       net.IP
	Protocol     uint8
	ProtocolData protocolData
	Direction    byte
}

type GenericProtocolData struct {
	Data byte
}

func (p *GenericProtocolData) Inverted() protocolData {
	return p
}

func (p *GenericProtocolData) ExpireDuration() time.Duration {
	return time.Minute
}

func (p *GenericProtocolData) Bytes() []byte {
	return []byte{p.Data}
}

type PortBasedProtocolData struct {
	SrcPort  uint16
	DestPort uint16
}

func (p *PortBasedProtocolData) Inverted() protocolData {
	return &PortBasedProtocolData{
		SrcPort:  p.DestPort,
		DestPort: p.SrcPort,
	}
}

func (p *PortBasedProtocolData) Bytes() []byte {
	buf := make([]byte, 4)
	buf[0] = byte(p.SrcPort >> 8)
	buf[1] = byte(p.SrcPort)
	buf[2] = byte(p.DestPort >> 8)
	buf[3] = byte(p.DestPort)
	return buf
}

func (p *PortBasedProtocolData) ExpireDuration() time.Duration {
	return time.Minute * 5
}

type ICMPProtocolData struct {
	Type uint8
	Code uint8
}

func (p *ICMPProtocolData) Inverted() protocolData {
	switch p.Type {
	case network.ICMPTypeEchoRequest:
		return &ICMPProtocolData{
			Type: network.ICMPTypeEchoReply,
			Code: p.Code,
		}
	case network.ICMPTypeEchoReply:
		return &ICMPProtocolData{
			Type: network.ICMPTypeEchoRequest,
			Code: p.Code,
		}
	default:
		return p
	}
}

func (p *ICMPProtocolData) Bytes() []byte {
	buf := make([]byte, 2)
	buf[0] = p.Type
	buf[1] = p.Code
	return buf
}

func (p *ICMPProtocolData) ExpireDuration() time.Duration {
	if p.Type == network.ICMPTypeEchoRequest || p.Type == network.ICMPv6TypeEchoRequest {
		return time.Second * 30
	}
	return time.Second
}

func getICMPProtocolData(pkt network.IPPacket) (*ICMPProtocolData, error) {
	payload := pkt.Bytes()[pkt.PayloadOffset():]
	icmpType := payload[0]
	icmpCode := payload[1]
	pd := &ICMPProtocolData{
		Type: icmpType,
		Code: icmpCode,
	}
	// for echo requests and replies, store the identifier too
	return pd, nil
}

func NewTuple(pkt network.IPPacket) (*Tuple, error) {
	family := byte(4)
	if pkt.Version() == 6 {
		family = byte(6)
	}
	protocol := pkt.Protocol()

	var (
		pd  protocolData
		err error
	)

	switch protocol {
	case network.ProtocolTCP, network.ProtocolUDP:
		pd = &PortBasedProtocolData{
			SrcPort:  pkt.SourcePort(),
			DestPort: pkt.DestinationPort(),
		}
	case network.ProtocolICMP:
		pd, err = getICMPProtocolData(pkt)
		if err != nil {
			return nil, err
		}
	default:
		pd = &GenericProtocolData{
			Data: protocol,
		}
	}

	// create a copy of source and destination ip
	srcIP := make([]byte, len(pkt.SourceIP()))
	copy(srcIP, pkt.SourceIP())
	destIP := make([]byte, len(pkt.DestinationIP()))
	copy(destIP, pkt.DestinationIP())

	return &Tuple{
		Family:       family,
		SrcIP:        srcIP,
		DestIP:       destIP,
		Protocol:     protocol,
		ProtocolData: pd,
		Direction:    byte(0),
	}, nil
}

func (t *Tuple) Inverted() *Tuple {
	return &Tuple{
		Family:       t.Family,
		SrcIP:        t.DestIP,
		DestIP:       t.SrcIP,
		Protocol:     t.Protocol,
		ProtocolData: t.ProtocolData.Inverted(),
		Direction:    t.Direction ^ 1,
	}
}

func (t *Tuple) ToKey() uint64 {
	var size int
	switch t.Family {
	case 4:
		size = 14
	case 6:
		size = 262
	}
	key := make([]byte, size)
	key = append(key, t.Family)
	key = append(key, t.SrcIP...)
	key = append(key, t.DestIP...)
	key = append(key, byte(t.Protocol))
	key = append(key, t.ProtocolData.Bytes()...)
	return xxhash.Sum64(key)
}

type Conntrack struct {
	cancel context.CancelFunc
	table  map[uint64]*ConnTrackEntry
	sync.RWMutex
}

type ConnTrackEntry struct {
	InMappedDst net.IP
	ExpireAt    atomic.Pointer[time.Time]
}

// IsExpired checks if the entry is expired.
func (e *ConnTrackEntry) IsExpired() bool {
	return e.ExpireAt.Load().Before(time.Now())
}

func (e *ConnTrackEntry) UpdateExpireAt(protocolData protocolData) {
	expireAt := time.Now().Add(protocolData.ExpireDuration())
	e.ExpireAt.Store(&expireAt)
}

func NewConntrack() *Conntrack {
	ct := &Conntrack{
		table: make(map[uint64]*ConnTrackEntry),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ct.cancel = cancel
	ct.lifeCycleHandler(ctx)
	return ct
}

func (c *Conntrack) Close() {
	c.cancel()
}

func (c *Conntrack) lifeCycleHandler(ctx context.Context) {
	go func() {
		t := time.NewTimer(time.Minute * 5)
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				c.Lock()
				clear(c.table)
				c.Unlock()
				return
			case <-t.C:
				c.Cleanup()
				t.Reset(time.Minute * 5)
			}
		}
	}()
}

func (c *Conntrack) LoadOrStore(tuple *Tuple, entry *ConnTrackEntry) (actual *ConnTrackEntry, loaded bool) {
	c.RLock()
	actual, exists := c.table[tuple.ToKey()]
	if exists && !entry.IsExpired() {
		c.RUnlock()
		return actual, true
	}
	c.RUnlock()

	c.Lock()
	defer c.Unlock()

	if !exists {
		actual = entry
	}

	c.store(tuple, actual)
	return actual, false
}

func (c *Conntrack) Store(tuple *Tuple, entry *ConnTrackEntry) {
	c.Lock()
	defer c.Unlock()
	c.store(tuple, entry)
}

func (c *Conntrack) store(tuple *Tuple, entry *ConnTrackEntry) {
	c.table[tuple.ToKey()] = entry
}

func (c *Conntrack) Load(tuple *Tuple) (*ConnTrackEntry, bool) {
	c.RLock()
	defer c.RUnlock()

	key := tuple.ToKey()
	entry, exists := c.table[key]
	if !exists {
		return nil, false
	}
	return entry, true
}

func (c *Conntrack) Delete(key uint64) {
	c.Lock()
	defer c.Unlock()

	c.delete(key)
}

func (c *Conntrack) delete(key uint64) {
	delete(c.table, key)
}

func (c *Conntrack) Cleanup() {
	c.Lock()
	defer c.Unlock()

	for key, entry := range c.table {
		if entry.IsExpired() {
			c.delete(key)
		}
	}
}
