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

package common

import "sync"

const (
	BufferSize512   = 512   // 2^9
	BufferSize1024  = 1024  // 2^10
	BufferSize2048  = 2048  // 2^11
	BufferSize4096  = 4096  // 2^12
	BufferSize65536 = 65536 // 2^16
)

// BufferPool provides Get and Put for []byte with size-tiered pooling.
type BufferPool interface {
	GetBuffer(minCap int) []byte
	PutBuffer(b []byte)
}

type bufferPool struct {
	pools []*sync.Pool
}

// NewBufferPool returns a new BufferPool with power-of-two size tiers.
func NewBufferPool() BufferPool {
	return &bufferPool{
		pools: []*sync.Pool{
			{New: func() any { return make([]byte, BufferSize512) }},
			{New: func() any { return make([]byte, BufferSize1024) }},
			{New: func() any { return make([]byte, BufferSize2048) }},
			{New: func() any { return make([]byte, BufferSize4096) }},
			{New: func() any { return make([]byte, BufferSize65536) }},
		},
	}
}

func (p *bufferPool) GetBuffer(minCap int) []byte {
	var pool *sync.Pool
	switch {
	case minCap <= BufferSize512:
		pool = p.pools[0]
	case minCap <= BufferSize1024:
		pool = p.pools[1]
	case minCap <= BufferSize2048:
		pool = p.pools[2]
	case minCap <= BufferSize4096:
		pool = p.pools[3]
	case minCap <= BufferSize65536:
		pool = p.pools[4]
	default:
		return make([]byte, minCap)
	}
	return pool.Get().([]byte)
}

func (p *bufferPool) PutBuffer(b []byte) {
	if b == nil {
		return
	}
	bCap := cap(b)
	switch {
	case bCap <= BufferSize512:
		p.pools[0].Put(b)
	case bCap <= BufferSize1024:
		p.pools[1].Put(b)
	case bCap <= BufferSize2048:
		p.pools[2].Put(b)
	case bCap <= BufferSize4096:
		p.pools[3].Put(b)
	case bCap <= BufferSize65536:
		p.pools[4].Put(b)
	}
}

// DefaultBufferPool is the package-level BufferPool for convenience.
var DefaultBufferPool BufferPool = NewBufferPool()

func GetBuffer(minCap int) any { return DefaultBufferPool.GetBuffer(minCap) }
func PutBuffer(b []byte)       { DefaultBufferPool.PutBuffer(b) }
