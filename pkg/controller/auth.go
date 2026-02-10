package controller

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) configureMTLS(mode config.Mode, cfg *config.AuthConfig, tlsConfig *tls.Config) error {
	if cfg.MTLS == nil {
		return nil
	}
	if mode == config.ModeClient {
		return c.configureClientMTLS(cfg, tlsConfig)
	}
	return c.configureServerMTLS(cfg, tlsConfig)
}

func (c *Controller) configureClientMTLS(cfg *config.AuthConfig, tlsConfig *tls.Config) error {
	if cfg.MTLS == nil {
		return nil
	}

	c.logger.Info("Configuring client MTLS")

	cert, err := tls.LoadX509KeyPair(cfg.MTLS.CertFile, cfg.MTLS.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	if cfg.MTLS.TrustPEM == "" {
		c.logger.Info("Using system CA for MTLS")
		return nil
	}

	ca, err := os.ReadFile(cfg.MTLS.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
		return fmt.Errorf("failed to append CA certs to pool")
	}

	return nil
}

func (c *Controller) configureServerMTLS(cfg *config.AuthConfig, tlsConfig *tls.Config) error {
	if cfg.MTLS == nil {
		return nil
	}

	c.logger.Info("Configuring server MTLS")

	if cfg.MTLS.TrustPEM == "" {
		return fmt.Errorf("MTLS is enabled but CA file is not provided")
	}

	ca, err := os.ReadFile(cfg.MTLS.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.ClientCAs.AppendCertsFromPEM(ca)

	return nil
}

func (c *Controller) createClientAuthenticator(cfg *config.AuthConfig) (common.Authenticator, error) {
	if cfg == nil {
		return nil, nil
	}

	if cfg.JWT == nil || cfg.JWT.Token == "" {
		return nil, nil
	}

	authenticator, err := jwt.NewClientAuthenticator(cfg.JWT.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
	}
	c.logger.Infof("JWT authentication enabled")
	return authenticator, nil
}

func (c *Controller) createServerAuthenticator(cfg *config.AuthConfig) (common.Authenticator, error) {
	if cfg == nil {
		return nil, nil
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
