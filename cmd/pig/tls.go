package main

import (
	"crypto/tls"
	"fmt"

	"github.com/riraccuia/pig/pkg/certificate"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
)

func createTLSConfig(logger *log.Logger, cfg *config.Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure,
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

	configureMTLS(logger, cfg, tlsCfg)

	if cfg.Mode == "client" {
		return tlsCfg, nil
	}

	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		return tlsCfg, nil
	}

	logger.Info("Generating self-signed TLS certificate")
	cert, err := certificate.GenerateCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{*cert}

	return tlsCfg, nil
}
