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
	"time"

	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/oauth2"
)

// ClientAuthenticator obtains an OAuth access_token (browser flow or refresh) and sends it using the same framing as pkg/auth/jwt.
type ClientAuthenticator struct {
	cfg   Config
	meta  *ProviderMetadata
	mu    sync.Mutex
	oauth *oauth2.Token
}

// NewClientAuthenticator builds a client authenticator. It performs OAuth discovery against cfg.IssuerURL.
func NewClientAuthenticator(cfg Config) (common.Authenticator, error) {
	if err := cfg.ValidateForClient(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient()
	ctx := context.Background()
	meta, err := FetchProviderMetadata(ctx, hc, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	return NewClientAuthenticatorFromMetadata(cfg, meta)
}

// NewClientAuthenticatorFromMetadata builds a client authenticator with pre-fetched provider metadata.
// Used by OIDC wrappers that discover via openid-configuration instead of RFC 8414.
func NewClientAuthenticatorFromMetadata(cfg Config, meta *ProviderMetadata) (common.Authenticator, error) {
	if err := cfg.ValidateForClient(); err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, fmt.Errorf("oauth: provider metadata is required")
	}
	if err := validateProviderMetadata(meta); err != nil {
		return nil, err
	}
	return &ClientAuthenticator{cfg: cfg, meta: meta}, nil
}

func (a *ClientAuthenticator) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     strings.TrimSpace(a.cfg.ClientID),
		ClientSecret: strings.TrimSpace(a.cfg.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.meta.AuthorizationEndpoint,
			TokenURL: a.meta.TokenEndpoint,
		},
		Scopes: a.cfg.scopeString(),
	}
}

// Acquire returns a usable OAuth token: reuses a non-expired access token, else refreshes, else runs the authorization code flow.
// Callers that need a fresh token response (for example OIDC reading Extra("id_token")) should use Refresh or Authorize.
func (a *ClientAuthenticator) Acquire(ctx context.Context) (*oauth2.Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acquireLocked(ctx)
}

func (a *ClientAuthenticator) acquireLocked(ctx context.Context) (*oauth2.Token, error) {
	if a.oauth != nil && a.oauth.Valid() {
		return a.oauth, nil
	}

	if tok, err := a.refreshLocked(ctx); err == nil {
		return tok, nil
	}

	return a.authorizeLocked(ctx)
}

// Refresh forces a refresh_token grant even if the access token is still valid.
// Returns an error when no refresh_token is cached or the refresh fails.
func (a *ClientAuthenticator) Refresh(ctx context.Context) (*oauth2.Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refreshLocked(ctx)
}

func (a *ClientAuthenticator) refreshLocked(ctx context.Context) (*oauth2.Token, error) {
	if a.oauth == nil || strings.TrimSpace(a.oauth.RefreshToken) == "" {
		return nil, fmt.Errorf("oauth: no refresh_token")
	}
	httpClient := a.cfg.httpClient()
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	oauthCfg := a.oauth2Config()

	// Force TokenSource to perform a refresh even when AccessToken is still valid.
	stale := *a.oauth
	stale.Expiry = time.Now().Add(-time.Hour)
	src := oauthCfg.TokenSource(oauthCtx, &stale)
	newTok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("oauth: refresh: %w", err)
	}
	if newTok == nil || strings.TrimSpace(newTok.AccessToken) == "" {
		return nil, fmt.Errorf("oauth: refresh returned empty access_token")
	}
	a.oauth = newTok
	return a.oauth, nil
}

// Authorize runs the authorization code flow (browser), replacing any cached credentials.
// Extra opts are appended to the authorization request (for example OIDC nonce).
func (a *ClientAuthenticator) Authorize(ctx context.Context, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authorizeLocked(ctx, opts...)
}

func (a *ClientAuthenticator) authorizeLocked(ctx context.Context, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	tok, err := runAuthorizationCodeFlow(ctx, &a.cfg, a.meta, opts...)
	if err != nil {
		return nil, err
	}
	if tok == nil || strings.TrimSpace(tok.AccessToken) == "" {
		return nil, fmt.Errorf("oauth: empty access_token")
	}
	a.oauth = tok
	return a.oauth, nil
}

// Authenticate obtains an access_token if needed, then writes it on rw using JWT framing.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	tok, err := a.acquireLocked(ctx)
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(tok.AccessToken); s != "" {
		return jwt.SendToken(rw, s)
	}
	return fmt.Errorf("oauth: empty access_token")
}
