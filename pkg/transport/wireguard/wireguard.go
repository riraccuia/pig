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
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport/wireguard/conn"
	wconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

type peerOpts struct {
	publicKeyHex    string
	presharedKeyHex string
	keepalive       int
	allowedIPs      []string
}

type setupOpts struct {
	privateKeyHex string
	peers         []peerOpts
	listenPort    int
	endpoint      string // applied to every peer when set (connect / Accept)
	mtu           int
	networkStr    string
	localAddr     *net.UDPAddr
	remoteAddr    *net.UDPAddr
}

// GetClientFromConn builds a WireGuard client over an ICE-nominated UDP socket.
func GetClientFromConn(ctx context.Context, co net.Conn, tunnelCfg *config.TunnelConfig, mtu int) (transport.Conn, error) {
	udpConn, ok := co.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("wireguard ice: expected *net.UDPConn, got %T", co)
	}
	opts, err := buildOptsFromConn(tunnelCfg, mtu, udpConn, true)
	if err != nil {
		return nil, err
	}
	bind := conn.NewSimpleBind(udpConn)
	wgConn, err := newConnWithBind(opts, bind)
	if err != nil {
		return nil, err
	}
	wgConn.underlyingConn = udpConn
	return wgConn, nil
	/*bind := conn.NewStdNetBind()
	if err := injectUDPConn(bind, udpConn); err != nil {
		return nil, err
	}
	return newConnWithBind(opts, bind)*/
}

// GetListenerFromConn builds a one-shot WireGuard listener over an ICE-nominated UDP socket.
func GetListenerFromConn(ctx context.Context, co net.Conn, tunnelCfg *config.TunnelConfig, mtu int) (transport.Listener, error) {
	udpConn, ok := co.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("wireguard ice: expected *net.UDPConn, got %T", co)
	}
	opts, err := buildOptsFromConn(tunnelCfg, mtu, udpConn, false)
	if err != nil {
		return nil, err
	}
	bind := conn.NewSimpleBind(udpConn)
	wgConn, err := newConnWithBind(opts, bind)
	if err != nil {
		return nil, err
	}
	wgConn.underlyingConn = udpConn
	return ice.NewListenerConn(wgConn, nil), nil
}

// GetClientDialFunc returns a function that creates WireGuard client connections.
func GetClientDialFunc(logger common.Logger, tunnelCfg *config.TunnelConfig, mtu int) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		opts, err := buildConnectOpts(tunnelCfg, mtu)
		if err != nil {
			return nil, err
		}
		return newConn(opts)
	}
}

// GetServerListenFunc returns a function that creates WireGuard listeners.
func GetServerListenFunc(logger common.Logger, tunnelCfg *config.TunnelConfig, mtu int) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		opts, err := buildListenOpts(tunnelCfg, mtu)
		if err != nil {
			return nil, err
		}
		return newSharedListener(opts)
	}
}

func buildConnectOpts(tunnelCfg *config.TunnelConfig, mtu int) (*setupOpts, error) {
	wg := tunnelCfg.Trust.WireGuard
	if wg == nil {
		return nil, fmt.Errorf("wireguard config not specified")
	}
	if len(wg.Peers) == 0 {
		return nil, fmt.Errorf("wireguard peers[0] required for connect")
	}
	privHex, err := base64KeyToHex(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	peer, err := peerOptsFromConfig(wg.Peers[0])
	if err != nil {
		return nil, err
	}
	endpoint := net.JoinHostPort(tunnelCfg.Connect.Address, strconv.Itoa(tunnelCfg.Connect.Port))
	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve endpoint: %w", err)
	}
	networkStr := transport.GetUDPNetworkString(remote.IP)
	return &setupOpts{
		privateKeyHex: privHex,
		peers:         []peerOpts{peer},
		listenPort:    tunnelCfg.Connect.SrcPort,
		endpoint:      endpoint,
		mtu:           mtu,
		networkStr:    networkStr,
		localAddr:     &net.UDPAddr{Port: tunnelCfg.Connect.SrcPort},
		remoteAddr:    remote,
	}, nil
}

func buildListenOpts(tunnelCfg *config.TunnelConfig, mtu int) (*setupOpts, error) {
	if tunnelCfg.Trust == nil || tunnelCfg.Trust.WireGuard == nil {
		return nil, fmt.Errorf("wireguard config not specified")
	}
	wg := tunnelCfg.Trust.WireGuard
	if len(wg.Peers) == 0 {
		return nil, fmt.Errorf("no wireguard peers configured")
	}
	privHex, err := base64KeyToHex(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	peers := make([]peerOpts, 0, len(wg.Peers))
	for i, p := range wg.Peers {
		peer, err := peerOptsFromConfig(p)
		if err != nil {
			return nil, fmt.Errorf("peers[%d]: %w", i, err)
		}
		peers = append(peers, peer)
	}
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(tunnelCfg.Listen.Address, strconv.Itoa(tunnelCfg.Listen.Port)))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve listen address: %w", err)
	}
	networkStr := transport.GetUDPNetworkString(laddr.IP)
	return &setupOpts{
		privateKeyHex: privHex,
		peers:         peers,
		listenPort:    tunnelCfg.Listen.Port,
		mtu:           mtu,
		networkStr:    networkStr,
		localAddr:     laddr,
		remoteAddr:    &net.UDPAddr{},
	}, nil
}

func peerOptsFromConfig(p config.WireGuardPeer) (peerOpts, error) {
	pubHex, err := base64KeyToHex(p.PublicKey)
	if err != nil {
		return peerOpts{}, fmt.Errorf("public_key: %w", err)
	}
	pskHex := ""
	if p.PresharedKey != "" {
		pskHex, err = base64KeyToHex(p.PresharedKey)
		if err != nil {
			return peerOpts{}, fmt.Errorf("preshared_key: %w", err)
		}
	}
	return peerOpts{
		publicKeyHex:    pubHex,
		presharedKeyHex: pskHex,
		keepalive:       p.Keepalive,
		allowedIPs:      append([]string(nil), p.AllowedIPs...),
	}, nil
}

func newConn(opts *setupOpts) (*Conn, error) {
	return newConnWithBind(opts, conn.NewDefaultBind())
}

func newConnWithBind(opts *setupOpts, bind wconn.Bind) (*Conn, error) {
	ft := newFakeTUN("pig-wg", opts.mtu)
	devLogger := device.NewLogger(device.LogLevelError, "wg: ")
	dev := device.NewDevice(ft, bind, devLogger)

	uapi := buildUAPI(opts)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		_ = ft.Close()
		return nil, fmt.Errorf("failed to configure wireguard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = ft.Close()
		return nil, fmt.Errorf("failed to bring up wireguard device: %w", err)
	}

	localAddr := opts.localAddr
	if port, err := listenPortFromIpc(dev); err == nil && port > 0 {
		// figure out the ephemeral port from the device
		localAddr.Port = port
	}

	return &Conn{
		dev:        dev,
		tun:        ft,
		localAddr:  localAddr,
		remoteAddr: opts.remoteAddr,
	}, nil
}

func buildUAPI(opts *setupOpts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", opts.privateKeyHex)
	fmt.Fprintf(&b, "listen_port=%d\n", opts.listenPort)
	fmt.Fprintf(&b, "replace_peers=true\n")
	for _, peer := range opts.peers {
		fmt.Fprintf(&b, "public_key=%s\n", peer.publicKeyHex)
		if peer.presharedKeyHex != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", peer.presharedKeyHex)
		}
		if opts.endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", opts.endpoint)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.keepalive)
		fmt.Fprintf(&b, "replace_allowed_ips=true\n")
		for _, cidr := range peer.allowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
		}
	}
	return b.String()
}

func base64KeyToHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}

func listenPortFromIpc(dev *device.Device) (int, error) {
	cfg, err := dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(cfg, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "listen_port" {
			continue
		}
		return strconv.Atoi(value)
	}
	return 0, fmt.Errorf("listen_port not found")
}

// buildOptsFromConn builds setupOpts from WireGuard trust config and a connected UDP socket.
func buildOptsFromConn(tunnelCfg *config.TunnelConfig, mtu int, udp *net.UDPConn, forConnect bool) (*setupOpts, error) {
	if tunnelCfg.Trust == nil || tunnelCfg.Trust.WireGuard == nil {
		return nil, fmt.Errorf("wireguard config not specified")
	}
	wg := tunnelCfg.Trust.WireGuard
	if len(wg.Peers) == 0 {
		return nil, fmt.Errorf("no wireguard peers configured")
	}
	privHex, err := base64KeyToHex(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	idx := len(wg.Peers)
	if forConnect {
		idx = 1
	}
	var peers []peerOpts
	for i, p := range wg.Peers[:idx] {
		peer, err := peerOptsFromConfig(p)
		if err != nil {
			return nil, fmt.Errorf("peers[%d]: %w", i, err)
		}
		peers = append(peers, peer)
	}
	local, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, fmt.Errorf("wireguard ice: missing local UDP addr")
	}
	remote, ok := udp.RemoteAddr().(*net.UDPAddr)
	if !ok || remote == nil {
		return nil, fmt.Errorf("wireguard ice: missing remote UDP addr (conn must be connected)")
	}
	return &setupOpts{
		privateKeyHex: privHex,
		peers:         peers,
		listenPort:    local.Port,
		endpoint:      remote.String(),
		mtu:           mtu,
		networkStr:    transport.GetUDPNetworkString(local.IP),
		localAddr:     local,
		remoteAddr:    remote,
	}, nil
}

func injectUDPConn(bind *conn.StdNetBind, udp *net.UDPConn) error {
	local, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return fmt.Errorf("wireguard ice: missing local UDP addr")
	}
	var v4, v6 *net.UDPConn
	if local.IP.To4() != nil {
		v4 = udp
	}
	if local.IP.To4() == nil {
		v6 = udp
	}
	bind.SetInjectedConns(v4, v6)
	return nil
}
