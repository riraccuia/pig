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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/auth/oauth"
	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/oauth2"
)

// ClientAuthenticator obtains an OIDC id_token via the oauth package and sends it using JWT framing.
type ClientAuthenticator struct {
	cfg     Config
	oauthCA *oauth.ClientAuthenticator
	mu      sync.Mutex
	idTok   string
}

// NewClientAuthenticator builds a client authenticator. It performs OIDC discovery for the code flow.
func NewClientAuthenticator(cfg Config) (common.Authenticator, error) {
	cfg = cfg.withClientScopes()
	if err := cfg.ValidateForClient(); err != nil {
		return nil, err
	}
	hc := cfg.httpClient()
	ctx := context.Background()
	meta, err := fetchProviderMetadata(ctx, hc, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	a, err := oauth.NewClientAuthenticatorFromMetadata(cfg.Config, meta)
	if err != nil {
		return nil, err
	}
	oauthCA, ok := a.(*oauth.ClientAuthenticator)
	if !ok {
		return nil, fmt.Errorf("oidc: unexpected oauth authenticator type")
	}
	return &ClientAuthenticator{cfg: cfg, oauthCA: oauthCA}, nil
}

func randomNonce() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func idTokenFromToken(tok *oauth2.Token) string {
	if tok == nil {
		return ""
	}
	raw, _ := tok.Extra("id_token").(string)
	return strings.TrimSpace(raw)
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

// requireIDTokenNonce checks that the id_token carries the nonce sent on the authorization request.
func requireIDTokenNonce(raw, expect string) error {
	expect = strings.TrimSpace(expect)
	if expect == "" {
		return fmt.Errorf("%w: empty expected nonce", ErrNonceMismatch)
	}
	claims := jwtgo.MapClaims{}
	_, _, err := jwtgo.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	got, _ := claims["nonce"].(string)
	got = strings.TrimSpace(got)
	if got == "" {
		return fmt.Errorf("%w: id_token missing nonce", ErrNonceMismatch)
	}
	if got != expect {
		return ErrNonceMismatch
	}
	return nil
}

// Authenticate obtains an id_token if needed, then writes it on rw using JWT framing.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	leeway := a.cfg.ClockSkewOrDefault()
	if idTokenStillValid(a.idTok, leeway) {
		return jwt.SendToken(rw, a.idTok)
	}

	// Prefer refresh so a still-valid access_token does not skip a new id_token.
	// Refresh responses are not bound to the authorization-request nonce.
	if tok, err := a.oauthCA.Refresh(ctx); err == nil {
		if id := idTokenFromToken(tok); id != "" {
			a.idTok = id
			return jwt.SendToken(rw, a.idTok)
		}
	}

	nonce := randomNonce()
	tok, err := a.oauthCA.Authorize(ctx, oauth2.SetAuthURLParam("nonce", nonce))
	if err != nil {
		return err
	}
	id := idTokenFromToken(tok)
	if id == "" {
		return ErrMissingIDToken
	}
	if err := requireIDTokenNonce(id, nonce); err != nil {
		return err
	}
	a.idTok = id
	return jwt.SendToken(rw, a.idTok)
}
