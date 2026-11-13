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
	"crypto/x509"
	"fmt"
	"os"

	"github.com/riraccuia/pig/pkg/certificate"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) createTLSConfig(direction config.TunnelDirection, cfg *config.TunnelConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSConfig.Insecure,
		MinVersion:         tls.VersionTLS13,
	}

	err := c.configureMTLS(direction, cfg.Trust, tlsCfg)
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

func (c *Controller) configureMTLS(direction config.TunnelDirection, cfg *config.TrustConfig, tlsConfig *tls.Config) error {
	if cfg == nil || cfg.MTLS == nil {
		return nil
	}
	if direction == config.TunnelDirectionConnect {
		return c.configureClientMTLS(cfg.MTLS, tlsConfig)
	}
	return c.configureServerMTLS(cfg.MTLS, tlsConfig)
}

func (c *Controller) configureClientMTLS(cfg *config.MTLSConfig, tlsConfig *tls.Config) error {
	if cfg == nil {
		return nil
	}

	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.TrustPEM == "" {
		return nil
	}

	c.logger.Info("Configuring peer trust for outbound TLS")

	ca, err := os.ReadFile(cfg.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}
	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
		return fmt.Errorf("failed to append CA certs to pool")
	}

	return nil
}

func (c *Controller) configureServerMTLS(cfg *config.MTLSConfig, tlsConfig *tls.Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.TrustPEM == "" {
		return nil
	}

	c.logger.Info("Configuring peer trust for inbound TLS")

	ca, err := os.ReadFile(cfg.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	tlsConfig.ClientCAs = x509.NewCertPool()
	if !tlsConfig.ClientCAs.AppendCertsFromPEM(ca) {
		return fmt.Errorf("failed to append CA certs to pool")
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return nil
}
