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
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/riraccuia/pig/pkg/common"
)

// ServerAuthenticator verifies an OIDC id_token sent with the same framing as pkg/auth/jwt.
// For providers that enable opaqueTokenFallback (e.g. GitHub), a non-JWT framed value is treated
// as an OAuth access_token and validated with provider-specific logic.
type ServerAuthenticator struct {
	cfg            Config
	expectedIss    string
	meta           *ProviderMetadata
	opaqueVerifier opaqueTokenVerifier
	claimRules     []claimRule
	mu             sync.RWMutex
	keySet         jwk.Set
}

// NewServerAuthenticator loads provider metadata and JWKS for cfg.IssuerURL.
func NewServerAuthenticator(cfg Config) (common.Authenticator, error) {
	if err := cfg.ValidateForServer(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient()
	ctx := context.Background()
	meta, err := fetchProviderMetadata(ctx, hc, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	cfgIss := NormalizeIssuer(cfg.IssuerURL)
	docIss := NormalizeIssuer(meta.Issuer)
	if !issuerMatchesDiscovery(cfgIss, docIss) {
		return nil, fmt.Errorf("oidc: issuer mismatch: config %q vs discovery %q", cfgIss, docIss)
	}
	ks, err := fetchJWKS(ctx, meta.JWKSURI)
	if err != nil {
		return nil, err
	}
	rules, err := parseClaimMatchers(cfg.ClaimMatchers)
	if err != nil {
		return nil, err
	}
	return &ServerAuthenticator{
		cfg:            cfg,
		expectedIss:    meta.Issuer,
		meta:           meta,
		opaqueVerifier: newOpaqueTokenVerifier(cfg, meta),
		claimRules:     rules,
		keySet:         ks,
	}, nil
}

func readFramedToken(r io.Reader) (string, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", fmt.Errorf("read token length: %w", err)
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	if n < 0 || n > 1<<16 {
		return "", fmt.Errorf("invalid token length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	return string(buf), nil
}

// Authenticate reads a framed id_token and verifies it against the configured issuer and audience.
func (a *ServerAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	raw, err := readFramedToken(rw)
	if err != nil {
		return err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrInvalidToken
	}
	if !tokenLooksLikeJWT(raw) {
		if a.opaqueVerifier == nil {
			return fmt.Errorf("%w: opaque bearer token not supported for this issuer", ErrInvalidToken)
		}
		return a.opaqueVerifier.verifyOpaque(ctx, a.cfg.httpClient(), raw, a.claimRules)
	}

	leeway := a.cfg.clockSkew()
	aud := a.cfg.effectiveAudience()

	a.mu.RLock()
	ks := a.keySet
	a.mu.RUnlock()

	tryVerify := func(set jwk.Set) error {
		claims, err := verifyIDToken(raw, a.expectedIss, aud, set, leeway)
		if err != nil {
			return err
		}
		return validateJWTClaimRules(claims, a.claimRules)
	}

	firstErr := tryVerify(ks)
	if firstErr == nil {
		return nil
	}
	newSet, ferr := fetchJWKS(ctx, a.meta.JWKSURI)
	if ferr != nil {
		return firstErr
	}
	a.mu.Lock()
	a.keySet = newSet
	a.mu.Unlock()
	if err := tryVerify(newSet); err != nil {
		return err
	}
	return nil
}
