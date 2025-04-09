package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

func configureMTLS(logger common.Logger, cfg *config.Config, tlsConfig *tls.Config) error {
	if cfg.Auth.MTLS == nil {
		return nil
	}
	if cfg.Mode == "client" {
		return configureClientMTLS(logger, cfg, tlsConfig)
	}
	return configureServerMTLS(logger, cfg, tlsConfig)
}

func configureClientMTLS(logger common.Logger, cfg *config.Config, tlsConfig *tls.Config) error {
	if cfg.Auth.MTLS == nil {
		return nil
	}

	logger.Info("Configuring client MTLS")

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	if cfg.Auth.MTLS.TrustPEM == "" {
		logger.Info("Using system CA for MTLS")
		return nil
	}

	ca, err := os.ReadFile(cfg.Auth.MTLS.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
		return fmt.Errorf("failed to append CA certs to pool")
	}

	return nil
}

func configureServerMTLS(logger common.Logger, cfg *config.Config, tlsConfig *tls.Config) error {
	if cfg.Auth.MTLS == nil {
		return nil
	}

	logger.Info("Configuring server MTLS")

	if cfg.Auth.MTLS.TrustPEM == "" {
		return fmt.Errorf("MTLS is enabled but CA file is not provided")
	}

	ca, err := os.ReadFile(cfg.Auth.MTLS.TrustPEM)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.ClientCAs.AppendCertsFromPEM(ca)

	return nil
}

func createClientAuthenticator(logger common.Logger, cfg *config.Config) (common.Authenticator, error) {
	if cfg.Auth == nil {
		return nil, nil
	}

	if cfg.Auth.JWT == nil || cfg.Auth.JWT.Token == "" {
		return nil, nil
	}

	authenticator, err := jwt.NewClientAuthenticator(cfg.Auth.JWT.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
	}
	logger.Infof("JWT authentication enabled")
	return authenticator, nil
}

func createServerAuthenticator(logger common.Logger, cfg *config.Config) (common.Authenticator, error) {
	if cfg.Auth == nil {
		return nil, nil
	}

	if cfg.Auth.JWT == nil || cfg.Auth.JWT.PublicKeySource == "" {
		return nil, nil
	}

	authenticator, err := jwt.NewServerAuthenticator(cfg.Auth.JWT.PublicKeySource)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
	}
	logger.Infof("JWT authentication enabled")
	return authenticator, nil
}
