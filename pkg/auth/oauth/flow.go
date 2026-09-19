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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func randomState() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type tokenResult struct {
	tok *oauth2.Token
	err error
}

// newAuthorizationCallbackHandler returns the loopback HTTP handler that validates the redirect,
// exchanges the authorization code, and sends at most one tokenResult on resultCh.
func newAuthorizationCallbackHandler(
	resultCh chan<- tokenResult,
	expectState string,
	flowCtx context.Context,
	oauthCfg *oauth2.Config,
	verifier string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errStr := strings.TrimSpace(q.Get("error")); errStr != "" {
			desc := strings.TrimSpace(q.Get("error_description"))
			resultCh <- tokenResult{nil, fmt.Errorf("%w: %s %s", ErrAuthorizationDenied, errStr, desc)}
			fmt.Fprintf(w, "Authorization error. You may close this window.")
			return
		}
		code := strings.TrimSpace(q.Get("code"))
		gotState := strings.TrimSpace(q.Get("state"))
		if gotState != expectState {
			resultCh <- tokenResult{nil, ErrInvalidState}
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		if code == "" {
			resultCh <- tokenResult{nil, fmt.Errorf("oauth: missing code in callback")}
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		var exchangeOpts []oauth2.AuthCodeOption
		if verifier != "" {
			exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
		}
		tok, err := oauthCfg.Exchange(flowCtx, code, exchangeOpts...)
		if err != nil {
			resultCh <- tokenResult{nil, fmt.Errorf("oauth: token exchange: %w", err)}
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}
		resultCh <- tokenResult{tok, nil}
		fmt.Fprintf(w, "Login successful. You may close this window.")
	}
}

// runAuthorizationCodeFlow runs the browser + loopback callback flow and returns the OAuth token.
// Providers that also return an id_token leave it in tok.Extra("id_token") for OIDC callers.
// Extra authOpts are appended to the authorization URL (e.g. oauth2.SetAuthURLParam("nonce", ...)).
func runAuthorizationCodeFlow(ctx context.Context, cfg *Config, meta *ProviderMetadata, extraAuthOpts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	httpClient := cfg.httpClient()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	oauthCfg := &oauth2.Config{
		ClientID:     strings.TrimSpace(cfg.ClientID),
		ClientSecret: strings.TrimSpace(cfg.ClientSecret),
		RedirectURL:  "",
		Endpoint: oauth2.Endpoint{
			AuthURL:  meta.AuthorizationEndpoint,
			TokenURL: meta.TokenEndpoint,
		},
		Scopes: cfg.scopeString(),
	}

	flowCtx, cancel := context.WithTimeout(ctx, cfg.callbackTimeout())
	defer cancel()

	var (
		lb             LoopbackRedirect
		err            error
		needCloseLn    bool
		shutdownServer = func(s *http.Server) {
			ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
			defer c()
			_ = s.Shutdown(ctx)
		}
	)

	switch {
	case strings.TrimSpace(cfg.RedirectURL) != "":
		lb, err = ListenFixedLoopbackRedirect(cfg)
	default:
		lb, err = ListenEphemeralLoopbackRedirect(cfg)
	}
	if err != nil {
		return nil, err
	}

	needCloseLn = true

	oauthCfg.RedirectURL = lb.RedirectURL

	verifier := ""
	var authOpts []oauth2.AuthCodeOption
	authOpts = append(authOpts, oauth2.AccessTypeOffline)
	if !cfg.DisablePKCE {
		verifier = oauth2.GenerateVerifier()
		authOpts = append(authOpts, oauth2.S256ChallengeOption(verifier))
	}
	authOpts = append(authOpts, extraAuthOpts...)

	state := randomState()
	authURL := oauthCfg.AuthCodeURL(state, authOpts...)

	if cfg.SkipOpenBrowser {
		if needCloseLn {
			_ = lb.Listener.Close()
		}
		return nil, &BrowserSkippedError{AuthURL: authURL}
	}

	if err := OpenURL(authURL); err != nil {
		if needCloseLn {
			_ = lb.Listener.Close()
		}
		return nil, fmt.Errorf("oauth: open browser: %w", err)
	}

	resultCh := make(chan tokenResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(lb.CallbackPath, newAuthorizationCallbackHandler(resultCh, state, flowCtx, oauthCfg, verifier))

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(lb.Listener)
	}()

	var res tokenResult
	select {
	case <-flowCtx.Done():
		shutdownServer(srv)
		return nil, fmt.Errorf("oauth: %w", flowCtx.Err())
	case res = <-resultCh:
		shutdownServer(srv)
		if res.err != nil {
			return nil, res.err
		}
		return res.tok, nil
	}
}
