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

package oidc

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/riraccuia/pig/pkg/certificate"
)

// LoopbackRedirect is the listener and OAuth redirect_uri values for a local callback server.
type LoopbackRedirect struct {
	Listener     net.Listener
	RedirectURL  string
	CallbackPath string
}

// ListenFixedLoopbackRedirect binds to the host:port in cfg.RedirectURL (loopback only).
// Scheme must be http or https. For https, a short-lived certificate from certificate.GenerateCertificate
// is used so the browser can complete the redirect without external file configuration.
func ListenFixedLoopbackRedirect(cfg *Config) (LoopbackRedirect, error) {
	raw := strings.TrimSpace(cfg.RedirectURL)
	if raw == "" {
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host != "127.0.0.1" && host != "localhost" {
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL host must be 127.0.0.1 or localhost for local callback server")
	}
	if u.Port() == "" {
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL must include explicit port for loopback listener")
	}
	if !strings.HasPrefix(u.Path, "/") {
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL path must start with /")
	}

	addr := net.JoinHostPort(host, u.Port())
	if host == "localhost" {
		addr = net.JoinHostPort("127.0.0.1", u.Port())
	}

	callbackPath := u.Path
	if strings.TrimSuffix(u.Path, "/") == "" {
		callbackPath = "/"
	}

	switch scheme {
	case "http":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return LoopbackRedirect{}, fmt.Errorf("oidc: listen redirect address: %w", err)
		}
		return LoopbackRedirect{Listener: ln, RedirectURL: raw, CallbackPath: callbackPath}, nil
	case "https":
		tcpLn, err := net.Listen("tcp", addr)
		if err != nil {
			return LoopbackRedirect{}, fmt.Errorf("oidc: listen redirect address: %w", err)
		}
		cert, err := certificate.GenerateCertificate()
		if err != nil {
			_ = tcpLn.Close()
			return LoopbackRedirect{}, fmt.Errorf("oidc: tls certificate for loopback: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
		ln := tls.NewListener(tcpLn, tlsCfg)
		return LoopbackRedirect{Listener: ln, RedirectURL: raw, CallbackPath: callbackPath}, nil
	default:
		return LoopbackRedirect{}, fmt.Errorf("oidc: RedirectURL scheme must be http or https, got %q", u.Scheme)
	}
}

// ListenEphemeralLoopbackRedirect listens on 127.0.0.1 with an ephemeral port and builds
// redirect_uri as http://127.0.0.1:<port><cfg.redirectPath()>.
func ListenEphemeralLoopbackRedirect(cfg *Config) (LoopbackRedirect, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return LoopbackRedirect{}, fmt.Errorf("oidc: listen loopback: %w", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	path := cfg.redirectPath()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", tcpAddr.Port, path)
	return LoopbackRedirect{
		Listener:     ln,
		RedirectURL:  redirectURI,
		CallbackPath: path,
	}, nil
}
