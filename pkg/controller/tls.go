package controller

import (
	"crypto/tls"
	"fmt"

	"github.com/riraccuia/pig/pkg/certificate"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) createTLSConfig(mode config.Mode, cfg *config.TunnelConfig) (*tls.Config, error) {
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

	err := c.configureMTLS(mode, cfg.Auth, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure MTLS: %w", err)
	}

	if mode == config.ModeClient {
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
