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
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/netstack"
	"github.com/riraccuia/pig/pkg/network"
)

const (
	proxyAdapterName       = "http_proxy"
	defaultProxyListenAddr = ":8080"
	proxyDialTimeout       = 30 * time.Second
	proxyLookupTimeout     = 5 * time.Second
	proxyReadHeaderTimeout = 30 * time.Second
	// IPv6 plus TCP headers; the resulting MSS also fits IPv4 datagrams in the MTU.
	proxyTCPIPOverhead = 60
)

var _ common.TunnelAdapter = (*ProxyAdapter)(nil)

// AdapterHTTPProxyConfig extends AdapterConfig with the local proxy settings.
type AdapterHTTPProxyConfig struct {
	Address []string
	MTU     int
	// ListenAddr is where local applications reach the HTTP/HTTPS proxy.
	ListenAddr string
	// DNSServer (host:port), when set, resolves target names through the
	// tunnel using DNS over TCP. Otherwise the system resolver is used.
	DNSServer string
	UseIPv6   bool
	Logger    common.Logger
}

// ProxyAdapter implements common.TunnelAdapter with a userspace TCP stack
// fronted by an HTTP/HTTPS proxy. Local applications connect to the proxy over
// OS TCP; the proxy dials resolved targets through the netstack, whose IP
// datagrams are exchanged with the tunnel through Read and Write. No TUN device
// or OS routing is involved.
type ProxyAdapter struct {
	logger        common.Logger
	stack         *netstack.Stack
	server        *http.Server
	listener      net.Listener
	resolver      *net.Resolver
	dnsServer     netip.AddrPort
	lookupNetwork string
	ip4           net.IP
	ipNet4        *net.IPNet
	ip6           net.IP
	ipNet6        *net.IPNet
	mtu           int
}

// NewProxyAdapter creates the netstack from cfg.Address (one IPv4 and/or one
// IPv6 CIDR) and starts serving the proxy on cfg.ListenAddr.
func NewProxyAdapter(cfg *AdapterHTTPProxyConfig) (*ProxyAdapter, error) {
	logger := cfg.Logger
	if logger == nil {
		return nil, errors.New("proxy adapter: logger is required")
	}
	if cfg.MTU <= proxyTCPIPOverhead {
		return nil, fmt.Errorf("proxy adapter: MTU %d too small", cfg.MTU)
	}
	a := &ProxyAdapter{logger: logger, mtu: cfg.MTU}
	if err := a.configureAddresses(cfg.Address, cfg.UseIPv6); err != nil {
		return nil, err
	}
	if err := a.setupResolver(cfg.DNSServer); err != nil {
		return nil, err
	}
	stack, err := netstack.New(logger, a.ip4, a.ip6, netstack.Options{MSS: cfg.MTU - proxyTCPIPOverhead})
	if err != nil {
		return nil, fmt.Errorf("proxy adapter: %w", err)
	}
	a.stack = stack

	listenAddr := cmp.Or(cfg.ListenAddr, defaultProxyListenAddr)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		stack.Close()
		return nil, fmt.Errorf("proxy adapter: listen %s: %w", listenAddr, err)
	}
	a.listener = ln
	a.server = &http.Server{Handler: a.newProxy(), ReadHeaderTimeout: proxyReadHeaderTimeout}
	go a.serve()
	logger.Infof("proxy adapter: HTTP proxy listening on %s", ln.Addr())
	return a, nil
}

func (a *ProxyAdapter) parseAddress(address []string, useIPv6 bool) error {
	for _, addr := range address {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return fmt.Errorf("proxy adapter: invalid address %s: %w", addr, err)
		}
		if a.ip4 == nil && prefix.Addr().Is4() {
			a.ip4 = prefix.Addr().AsSlice()
			a.ipNet4 = &net.IPNet{
				IP:   a.ip4,
				Mask: net.CIDRMask(prefix.Bits(), 32),
			}
			a.lookupNetwork = "ip4"
			if !useIPv6 {
				return nil
			}
		}
		if !useIPv6 {
			continue
		}
		if a.ip6 == nil && prefix.Addr().Is6() {
			a.ip6 = prefix.Addr().AsSlice()
			a.ipNet6 = &net.IPNet{
				IP:   a.ip6,
				Mask: net.CIDRMask(prefix.Bits(), 128),
			}
			a.lookupNetwork = "ip6"
			if a.ip4 != nil {
				return nil
			}
		}
	}
	return errors.New("proxy adapter: invalid tunnel address")
}

func (a *ProxyAdapter) configureAddresses(address []string, useIPv6 bool) error {
	if address != nil {
		return a.parseAddress(address, useIPv6)
	}
	prefix, err := network.GenerateIPPrefix("100.64.0.0/11", 32, true)
	if err != nil {
		return err
	}
	a.ip4 = prefix.Addr().AsSlice()
	a.ipNet4 = &net.IPNet{
		IP:   a.ip4,
		Mask: net.CIDRMask(prefix.Bits(), 32),
	}
	if !useIPv6 {
		a.lookupNetwork = "ip4"
		return nil
	}
	prefix, err = network.GenerateIPPrefix("fd00::/8", 128, true)
	if err != nil {
		return err
	}
	a.ip6 = prefix.Addr().AsSlice()
	a.ipNet6 = &net.IPNet{
		IP:   a.ip6,
		Mask: net.CIDRMask(prefix.Bits(), 128),
	}
	a.lookupNetwork = "ip6"
	return nil
}

func (a *ProxyAdapter) setupResolver(dnsServer string) error {
	a.resolver = net.DefaultResolver
	if dnsServer == "" {
		return nil
	}
	server, err := netip.ParseAddrPort(dnsServer)
	if err != nil {
		return fmt.Errorf("proxy adapter: DNS server %s: %w", dnsServer, err)
	}
	a.dnsServer = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	a.resolver = &net.Resolver{PreferGo: true, Dial: a.dialDNS}
	return nil
}

// dialDNS hands the Go resolver a netstack UDP connection.
func (a *ProxyAdapter) dialDNS(ctx context.Context, _, _ string) (net.Conn, error) {
	return a.stack.DialUDP(net.UDPAddrFromAddrPort(a.dnsServer))
}

// newProxy routes both CONNECT tunnels and plain HTTP requests through
// dialContext. goproxy's default transport skips TLS verification and honors
// proxy environment variables, so it is replaced.
func (a *ProxyAdapter) newProxy() *goproxy.ProxyHttpServer {
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

func (a *ProxyAdapter) serve() {
	err := a.server.Serve(a.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return
	}
	a.logger.Errorf("proxy adapter: serve: %v", err)
}

// dialContext resolves address and dials each candidate through the netstack
// until one connects.
func (a *ProxyAdapter) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy adapter: unsupported network %s", network)
	}
	host, portName, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("proxy adapter: %w", err)
	}
	port, err := a.resolver.LookupPort(ctx, "tcp", portName)
	if err != nil {
		return nil, fmt.Errorf("proxy adapter: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, proxyDialTimeout)
	defer cancel()
	addrs, err := a.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("proxy adapter: resolve %s: %w", host, err)
	}

	var errs []error
	for _, addr := range addrs {
		target := netip.AddrPortFrom(addr, uint16(port))
		conn, err := a.stack.Dial(ctx, net.TCPAddrFromAddrPort(target))
		if err == nil {
			a.logger.Debugf("proxy adapter: connected to %s (%s)", address, target)
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", target, err))
	}
	return nil, fmt.Errorf("proxy adapter: dial %s: %w", address, errors.Join(errs...))
}

// resolve returns the addresses of host that the netstack has a local
// address family for.
func (a *ProxyAdapter) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, proxyLookupTimeout)
	defer cancel()

	addrs, err := a.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	//a.logger.Debugf("proxy adapter: resolved %s to %v", host, addrs)
	reachable := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if (addr.Is4() && a.ip4 != nil) || (addr.Is6() && a.ip6 != nil) {
			reachable = append(reachable, addr)
		}
	}
	if len(reachable) == 0 {
		return nil, errors.New("no address in a tunnel address family")
	}
	return reachable, nil
}

func (a *ProxyAdapter) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	return a.resolver.LookupNetIP(ctx, a.lookupNetwork, host)
}

// ProxyAddr returns the address local applications use to reach the proxy.
func (a *ProxyAdapter) ProxyAddr() net.Addr {
	return a.listener.Addr()
}

func (a *ProxyAdapter) SetDeadline(t time.Time) error {
	return a.SetReadDeadline(t)
}

func (a *ProxyAdapter) SetReadDeadline(t time.Time) error {
	return a.stack.SetReadDeadline(t)
}

func (a *ProxyAdapter) SetWriteDeadline(t time.Time) error {
	// not implemented
	return nil
}

func (a *ProxyAdapter) Read(buf []byte) (int, error) {
	return a.stack.Read(buf)
}

func (a *ProxyAdapter) Write(b []byte) (int, error) {
	return a.stack.Write(b)
}

// Close stops the proxy and tears down every netstack connection, which also
// ends the proxied client connections.
func (a *ProxyAdapter) Close() error {
	return errors.Join(a.server.Close(), a.stack.Close())
}

func (a *ProxyAdapter) MTU() int {
	return a.mtu
}

func (a *ProxyAdapter) BlockSize() int {
	return a.mtu
}

func (a *ProxyAdapter) IP() net.IP {
	return a.ip4
}

func (a *ProxyAdapter) IPNet() *net.IPNet {
	return a.ipNet4
}

func (a *ProxyAdapter) IP6() net.IP {
	return a.ip6
}

func (a *ProxyAdapter) IPNet6() *net.IPNet {
	return a.ipNet6
}

func (a *ProxyAdapter) Name() string {
	return proxyAdapterName
}

func (a *ProxyAdapter) Index() int {
	return -1
}

// proxyLogger adapts common.Logger to goproxy's Printf logger.
type proxyLogger struct {
	logger common.Logger
}

func (l proxyLogger) Printf(format string, args ...any) {
	l.logger.Debugf("proxy adapter: "+format, args...)
}
