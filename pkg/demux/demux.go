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

package demux

import (
	"context"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

type Demux struct {
	logger     common.Logger
	adapter    common.TunnelAdapter
	mtu        int
	inbound    common.PacketQueue
	outbound   common.PacketQueue
	routeTable *routeTable
	bufferPool common.BufferPool
}

func New(logger common.Logger, adapter common.TunnelAdapter, mtu int) *Demux {
	return &Demux{
		logger:     logger,
		adapter:    adapter,
		mtu:        mtu,
		inbound:    make(common.PacketQueue, 1024),
		outbound:   make(common.PacketQueue, 1024),
		routeTable: newRouteTable(),
		bufferPool: common.DefaultBufferPool,
	}
}

func (d *Demux) Start(ctx context.Context) {
	go d.readFromAdapter(ctx)
	go d.writeToAdapter(ctx)
	go d.readFromOutbound(ctx)
}

func (d *Demux) AddRoutes(ta *Adapter, routes []config.Route) {
	d.routeTable.addRoutes(ta, routes)
}

func (d *Demux) RemoveRoutes(ta *Adapter) {
	d.routeTable.removeRoutes(ta)
}

func (d *Demux) SetDefault(ta *Adapter) {
	d.routeTable.setDefault(ta)
}

func (d *Demux) WithBufferPool(bufferPool common.BufferPool) *Demux {
	d.bufferPool = bufferPool
	return d
}
