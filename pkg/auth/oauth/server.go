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

package oauth

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/riraccuia/pig/pkg/common"
)

// ServerAuthenticator verifies an OAuth access token sent with the same framing as pkg/auth/jwt.
// Verification order:
//  1. Provider-specific opaque validation when the issuer supports it (e.g. GitHub REST, Google tokeninfo)
//  2. JWT access token validation when the token looks like a JWT and discovery provides jwks_uri
//  3. Otherwise a clear error (introspection is not implemented)
type ServerAuthenticator struct {
	cfg            Config
	meta           *ProviderMetadata
	opaqueVerifier opaqueTokenVerifier
	claimRules     []ClaimRule
	expectedIss    string
	mu             sync.RWMutex
	keySet         jwk.Set
}

// NewServerAuthenticator loads provider metadata for cfg.IssuerURL and selects available verifiers.
func NewServerAuthenticator(cfg Config) (common.Authenticator, error) {
	if err := cfg.ValidateForServer(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient()
	ctx := context.Background()
	meta, err := FetchProviderMetadata(ctx, hc, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	cfgIss := NormalizeIssuer(cfg.IssuerURL)
	docIss := NormalizeIssuer(meta.Issuer)
	if !issuerMatchesDiscovery(cfgIss, docIss) {
		return nil, fmt.Errorf("oauth: issuer mismatch: config %q vs discovery %q", cfgIss, docIss)
	}
	rules, err := ParseClaimMatchers(cfg.ClaimMatchers)
	if err != nil {
		return nil, err
	}

	opaque := newOpaqueTokenVerifier(cfg, meta)

	var keySet jwk.Set
	if jwks := strings.TrimSpace(meta.JWKSURI); jwks != "" {
		keySet, err = fetchJWKS(ctx, jwks)
		if err != nil {
			return nil, err
		}
	}

	if opaque == nil && keySet == nil {
		return nil, fmt.Errorf("oauth: no token verification method for issuer %q (no provider-specific opaque verifier and no jwks_uri)", meta.Issuer)
	}
	if opaque == nil && cfg.EffectiveAudience() == "" {
		return nil, fmt.Errorf("oauth: ClientID or ExpectedAudience is required to verify JWT access tokens for issuer %q", meta.Issuer)
	}

	return &ServerAuthenticator{
		cfg:            cfg,
		meta:           meta,
		opaqueVerifier: opaque,
		claimRules:     rules,
		expectedIss:    meta.Issuer,
		keySet:         keySet,
	}, nil
}

// ReadFramedToken reads a 2-byte length-prefixed token from r.
func ReadFramedToken(r io.Reader) (string, error) {
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

// Authenticate reads a framed access token and verifies it.
func (a *ServerAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	raw, err := ReadFramedToken(rw)
	if err != nil {
		return err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ErrInvalidToken
	}

	// 1. Provider-specific opaque (e.g. GitHub).
	if a.opaqueVerifier != nil {
		return a.opaqueVerifier.verifyOpaque(ctx, a.cfg.httpClient(), raw, a.claimRules)
	}

	// 3. JWT access token via JWKS.
	if tokenLooksLikeJWT(raw) && a.keySet != nil {
		return a.verifyJWT(ctx, raw)
	}

	// 4. No applicable method.
	if tokenLooksLikeJWT(raw) {
		return fmt.Errorf("%w: JWT access token received but jwks_uri is unavailable for issuer %q", ErrInvalidToken, a.meta.Issuer)
	}
	return fmt.Errorf("%w: opaque access token not supported for issuer %q (token introspection not implemented)", ErrInvalidToken, a.meta.Issuer)
}

func (a *ServerAuthenticator) verifyJWT(ctx context.Context, raw string) error {
	aud := a.cfg.EffectiveAudience()
	if aud == "" {
		return fmt.Errorf("%w: ClientID or ExpectedAudience is required to validate JWT access token audience", ErrInvalidToken)
	}
	leeway := a.cfg.ClockSkewOrDefault()

	a.mu.RLock()
	ks := a.keySet
	a.mu.RUnlock()

	tryVerify := func(set jwk.Set) error {
		claims, err := verifyAccessTokenJWT(raw, a.expectedIss, aud, set, leeway)
		if err != nil {
			return err
		}
		return ValidateJWTClaimRules(claims, a.claimRules)
	}

	firstErr := tryVerify(ks)
	if firstErr == nil {
		return nil
	}
	jwksURI := strings.TrimSpace(a.meta.JWKSURI)
	if jwksURI == "" {
		return firstErr
	}
	newSet, ferr := fetchJWKS(ctx, jwksURI)
	if ferr != nil {
		return firstErr
	}
	a.mu.Lock()
	a.keySet = newSet
	a.mu.Unlock()
	return tryVerify(newSet)
}
