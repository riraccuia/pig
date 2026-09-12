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
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/oauth2"
)

// ClientAuthenticator obtains an OIDC id_token (browser flow or refresh) and sends it using the same framing as pkg/auth/jwt.
// For supported providers (e.g. GitHub) when no id_token is returned, it sends the OAuth access_token instead.
type ClientAuthenticator struct {
	cfg   Config
	meta  *ProviderMetadata
	mu    sync.Mutex
	idTok string
	oauth *oauth2.Token
}

// NewClientAuthenticator builds a client authenticator. It performs OIDC discovery against cfg.IssuerURL.
func NewClientAuthenticator(cfg Config) (common.Authenticator, error) {
	if err := cfg.ValidateForClient(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient()
	ctx := context.Background()
	meta, err := fetchProviderMetadata(ctx, hc, cfg.IssuerURL)
	if err != nil {
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

func idTokenStillValid(raw string, leeway time.Duration) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	claims := jwtgo.MapClaims{}
	_, _, err := jwtgo.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return false
	}
	return exp.After(time.Now().Add(leeway))
}

// Authenticate obtains an id_token if needed, then writes it on rw using JWT framing.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	httpClient := a.cfg.httpClient()
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	leeway := a.cfg.clockSkew()

	if idTokenStillValid(a.idTok, leeway) {
		return jwt.SendToken(rw, a.idTok)
	}

	if a.oauth != nil && a.oauth.RefreshToken != "" {
		oauthCfg := a.oauth2Config()
		src := oauthCfg.TokenSource(oauthCtx, a.oauth)
		newTok, err := src.Token()
		if err == nil {
			if raw, ok := newTok.Extra("id_token").(string); ok && strings.TrimSpace(raw) != "" {
				a.idTok = raw
				a.oauth = newTok
				return jwt.SendToken(rw, a.idTok)
			}
			a.oauth = newTok
			if providerSupportsOpaqueTokenFallback(a.cfg, a.meta) {
				if s := strings.TrimSpace(newTok.AccessToken); s != "" {
					a.idTok = ""
					return jwt.SendToken(rw, s)
				}
			}
		}
	}

	if providerSupportsOpaqueTokenFallback(a.cfg, a.meta) && a.oauth != nil {
		if s := strings.TrimSpace(a.oauth.AccessToken); s != "" {
			a.idTok = ""
			return jwt.SendToken(rw, s)
		}
	}

	idRaw, tok, err := runAuthorizationCodeFlow(ctx, &a.cfg, a.meta)
	if err != nil {
		return err
	}
	a.oauth = tok
	if s := strings.TrimSpace(idRaw); s != "" {
		a.idTok = s
		return jwt.SendToken(rw, a.idTok)
	}
	if providerSupportsOpaqueTokenFallback(a.cfg, a.meta) {
		if s := strings.TrimSpace(tok.AccessToken); s != "" {
			a.idTok = ""
			return jwt.SendToken(rw, s)
		}
		return fmt.Errorf("oidc: no id_token and empty access_token")
	}
	return ErrMissingIDToken
}
