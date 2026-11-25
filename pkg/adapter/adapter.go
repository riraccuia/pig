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

package adapter

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/common"
)

type AdapterType string

const (
	AdapterTypeTun        AdapterType = "tun"
	AdapterTypeStdio      AdapterType = "stdio"
	AdapterTypeHTTPProxy  AdapterType = "http_proxy"
	AdapterTypeSocksProxy AdapterType = "socks_proxy"
)

type AdapterConfig struct {
	Type    AdapterType
	Address []string
	MTU     int
	// MultiQueue enables tun multi-queue support.
	// It is only valid on Linux platforms.
	MultiQueue bool
	Logger     common.Logger
}

func NewAdapter(logger common.Logger, adapterType AdapterType, cfg any) (common.TunnelAdapter, error) {
	switch adapterType {
	case AdapterTypeTun:
		cfg := cfg.(*AdapterConfig)
		return NewTunAdapter(cfg)
	case AdapterTypeStdio:
		cfg := cfg.(*AdapterStdIOConfig)
		return NewStdioAdapter(cfg)
	case AdapterTypeHTTPProxy:
		cfg := cfg.(*AdapterHTTPProxyConfig)
		cfg.Logger = logger
		return NewProxyHTTPAdapter(cfg)
	case AdapterTypeSocksProxy:
		cfg := cfg.(*AdapterSocksProxyConfig)
		cfg.Logger = logger
		return NewProxySocksAdapter(cfg)
	default:
		return nil, fmt.Errorf("invalid adapter type: %s", adapterType)
	}
}
