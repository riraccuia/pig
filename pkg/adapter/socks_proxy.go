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
	"context"
	"errors"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/things-go/go-socks5"
)

const proxySocksAdapterName = "socks_proxy"

var (
	_ common.TunnelAdapter = (*ProxySocksAdapter)(nil)
	_ socks5.NameResolver  = (*ProxySocksAdapter)(nil)
)

// AdapterSocksProxyConfig extends AdapterConfig with the local proxy settings.
type AdapterSocksProxyConfig struct {
	AdapterBackendProxyConfig
}

// ProxySocksAdapter implements common.TunnelAdapter with a userspace TCP stack
// fronted by a SOCKS5 proxy. Local applications connect to the proxy over
// OS TCP; the proxy dials resolved targets through the netstack, whose IP
// datagrams are exchanged with the tunnel through Read and Write. No TUN device
// or OS routing is involved.
type ProxySocksAdapter struct {
	*proxyBackend
	server *socks5.Server
}

// socksLogger adapts common.Logger to go-socks5's Logger.
type socksLogger struct {
	logger common.Logger
}

func (l socksLogger) Errorf(format string, args ...any) {
	l.logger.Errorf("proxy adapter: "+format, args...)
}

// NewProxySocksAdapter creates the proxy backend and starts serving the proxy on cfg.ListenAddr.
func NewProxySocksAdapter(cfg *AdapterSocksProxyConfig) (*ProxySocksAdapter, error) {
	pb, err := NewProxyBackend(&cfg.AdapterBackendProxyConfig)
	if err != nil {
		return nil, err
	}
	a := &ProxySocksAdapter{proxyBackend: pb}
	a.server = socks5.NewServer(
		socks5.WithLogger(socksLogger{logger: a.logger}),
		socks5.WithDial(a.dialContext),
		socks5.WithResolver(a),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true, EnableAssociate: true}),
	)
	go a.serve()
	a.logger.Infof("proxy adapter: SOCKS proxy listening on %s", a.listener.Addr())
	return a, nil
}

// Resolve implements socks5.NameResolver using the proxy backend's tunnel resolver.
func (a *ProxySocksAdapter) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := a.resolve(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addrs[0].AsSlice(), nil
}

func (a *ProxySocksAdapter) serve() {
	err := a.server.Serve(a.listener)
	if errors.Is(err, net.ErrClosed) {
		return
	}
	a.logger.Errorf("proxy adapter: serve: %v", err)
}

func (a *ProxySocksAdapter) Name() string {
	return proxySocksAdapterName
}
