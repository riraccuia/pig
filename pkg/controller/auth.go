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

	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/auth/oidc"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) configureMTLS(direction config.TunnelDirection, cfg *config.AuthConfig, tlsConfig *tls.Config) error {
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

func (c *Controller) createClientAuthenticator(cfg *config.AuthConfig) (authenticator common.Authenticator, err error) {
	if cfg == nil || cfg.Type == config.AuthTypeNone {
		return nil, nil
	}

	if !cfg.Type.IsValid() {
		return nil, fmt.Errorf("invalid authentication type: %s", cfg.Type)
	}

	switch cfg.Type {
	case config.AuthTypeOIDC:
		if cfg.OIDC == nil {
			return nil, fmt.Errorf("invalid oidc authentication config")
		}
		authenticator, err = oidc.NewClientAuthenticator(cfg.OIDC.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC authenticator: %w", err)
		}
		c.logger.Infof("OIDC authentication enabled")
	case config.AuthTypeJWT:
		if cfg.JWT == nil || cfg.JWT.Token == "" {
			return nil, fmt.Errorf("invalid jwt authentication config")
		}
		authenticator, err = jwt.NewClientAuthenticator(cfg.JWT.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
		}
		c.logger.Infof("JWT authentication enabled")
	default:
		return nil, fmt.Errorf("authentication type not implemented: %s", cfg.Type)
	}
	return authenticator, nil
}

func (c *Controller) createServerAuthenticator(cfg *config.AuthConfig) (common.Authenticator, error) {
	if cfg == nil {
		return nil, nil
	}

	if cfg.OIDC != nil {
		authenticator, err := oidc.NewServerAuthenticator(cfg.OIDC.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC authenticator: %w", err)
		}
		c.logger.Infof("OIDC authentication enabled")
		return authenticator, nil
	}

	if cfg.JWT == nil || cfg.JWT.PublicKeySource == "" {
		return nil, nil
	}

	authenticator, err := jwt.NewServerAuthenticator(cfg.JWT.PublicKeySource)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
	}
	c.logger.Infof("JWT authentication enabled")
	return authenticator, nil
}
