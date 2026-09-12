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

package controller

import (
	"crypto/tls"
	"fmt"

	"github.com/riraccuia/pig/pkg/certificate"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) createTLSConfig(direction config.TunnelDirection, cfg *config.TunnelConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSConfig.Insecure,
		MinVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
	}

	err := c.configureMTLS(direction, cfg.Auth, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure MTLS: %w", err)
	}

	if direction == config.TunnelDirectionConnect {
		return tlsCfg, nil
	}

	if cfg.TLSConfig.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSConfig.CertFile, cfg.TLSConfig.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		return tlsCfg, nil
	}

	c.logger.Info("Generating self-signed TLS certificate")
	cert, err := certificate.GenerateCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{*cert}

	return tlsCfg, nil
}
