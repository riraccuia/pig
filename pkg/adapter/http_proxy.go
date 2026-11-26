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
	"errors"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/riraccuia/pig/pkg/common"
)

const proxyHTTPAdapterName = "http_proxy"

// AdapterHTTPProxyConfig extends AdapterConfig with the local proxy settings.
type AdapterHTTPProxyConfig struct {
	AdapterBackendProxyConfig
}

// ProxyHTTPAdapter implements common.TunnelAdapter with a userspace TCP stack
// fronted by an HTTP/HTTPS proxy. Local applications connect to the proxy over
// OS TCP; the proxy dials resolved targets through the netstack, whose IP
// datagrams are exchanged with the tunnel through Read and Write. No TUN device
// or OS routing is involved.
type ProxyHTTPAdapter struct {
	*proxyBackend
	server *http.Server
}

// proxyLogger adapts common.Logger to goproxy's Printf logger.
type proxyLogger struct {
	logger common.Logger
}

func (l proxyLogger) Printf(format string, args ...any) {
	l.logger.Debugf("proxy adapter: "+format, args...)
}

// NewProxyHTTPAdapter creates the proxy backend and starts serving the proxy on cfg.ListenAddr.
func NewProxyHTTPAdapter(cfg *AdapterHTTPProxyConfig) (*ProxyHTTPAdapter, error) {
	pb, err := NewProxyBackend(&cfg.AdapterBackendProxyConfig)
	if err != nil {
		return nil, err
	}
	a := &ProxyHTTPAdapter{proxyBackend: pb}
	a.server = &http.Server{Handler: a.newProxy(), ReadHeaderTimeout: proxyReadHeaderTimeout}
	go a.serve()
	a.logger.Infof("proxy adapter: HTTP proxy listening on %s", a.listener.Addr())
	return a, nil
}

// newProxy routes both CONNECT tunnels and plain HTTP requests through
// dialContext. goproxy's default transport skips TLS verification and honors
// proxy environment variables, so it is replaced.
func (a *ProxyHTTPAdapter) newProxy() *goproxy.ProxyHttpServer {
	px := goproxy.NewProxyHttpServer()
	px.Logger = proxyLogger{logger: a.logger}
	px.ConnectDial = nil
	px.Tr = &http.Transport{
		DialContext:           a.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return px
}

func (a *ProxyHTTPAdapter) serve() {
	err := a.server.Serve(a.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return
	}
	a.logger.Errorf("proxy adapter: serve: %v", err)
}

func (a *ProxyHTTPAdapter) Name() string {
	return proxyHTTPAdapterName
}

// Close stops the proxy and tears down every netstack connection, which also
// ends the proxied client connections.
func (a *ProxyHTTPAdapter) Close() error {
	return errors.Join(a.server.Close(), a.proxyBackend.Close())
}
