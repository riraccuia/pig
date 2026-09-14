//go:build manual

package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestManualGitHubOAuthClientFlow runs the interactive authorization-code + PKCE flow against GitHub OIDC.
// It does not run unless MANUAL_GITHUB_OIDC=1 is set (avoids hanging CI and surprise browser opens).
// Register redirect URI in the GitHub OAuth app: http://127.0.0.1:12345/oauth2/callback
// Optional: GITHUB_OIDC_CLIENT_SECRET if your OAuth app is confidential.
func TestManualGitHubOAuthClientFlow(t *testing.T) {
	/*if os.Getenv("MANUAL_GITHUB_OIDC") != "1" {
		t.Skip("set MANUAL_GITHUB_OIDC=1 to run manual GitHub OAuth (opens browser)")
	}*/

	ctx := context.Background()
	cfg := Config{
		IssuerURL:    IssuerGitHub,
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		//RedirectURL:     "http://127.0.0.1:12345/oauth2/callback",
		Scopes: []string{"user:email", "read:user"},
		ClaimMatchers: map[string]any{
			"email": []string{"your-email@example.com"},
		},
	}

	ca, err := NewClientAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = ca.Authenticate(ctx, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}

	tok := ca.(*ClientAuthenticator).oauth

	var githubAPIUser map[string]any
	{
		at := strings.TrimSpace(tok.AccessToken)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+at)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "qt-manual-github-oidc-test")
		resp, err := cfg.httpClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(body))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("github api /user: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var emails []map[string]any
		if err := json.Unmarshal(body, &emails); err != nil {
			t.Fatal(err)
		}
		githubAPIUser = emails[0]
	}

	out := map[string]any{
		"access_token":    tok.AccessToken,
		"token_type":      tok.TokenType,
		"refresh_token":   tok.RefreshToken,
		"github_api_user": githubAPIUser,
	}
	if !tok.Expiry.IsZero() {
		out["expiry"] = tok.Expiry.Format(time.RFC3339Nano)
	}
	if extra := tokExtraJSON(tok); len(extra) > 0 {
		out["extra"] = extra
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		t.Fatal(err)
	}

	sa, err := NewServerAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := []byte(tok.AccessToken)
	lenBuf := []byte{byte(len(at) >> 8), byte(len(at))}
	err = sa.Authenticate(ctx, bytes.NewBuffer(append(lenBuf, at...)))
	if err != nil {
		t.Fatal(err)
	}
}

func TestManualGoogleOAuthClientFlow(t *testing.T) {
	/*if os.Getenv("MANUAL_GITHUB_OIDC") != "1" {
		t.Skip("set MANUAL_GITHUB_OIDC=1 to run manual GitHub OAuth (opens browser)")
	}*/

	ctx := context.Background()
	cfg := Config{
		IssuerURL:    IssuerGoogle,
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		Scopes:       []string{"profile", "email"},
		//RedirectURL:     "http://127.0.0.1:12345/oauth2/callback",
		ClaimMatchers: map[string]any{
			"email": []string{"user@example.com"},
		},
	}

	ca, err := NewClientAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = ca.Authenticate(ctx, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}

	tok := ca.(*ClientAuthenticator).oauth

	out := map[string]any{
		"token_type":    tok.TokenType,
		"refresh_token": tok.RefreshToken,
	}
	if !tok.Expiry.IsZero() {
		out["expiry"] = tok.Expiry.Format(time.RFC3339Nano)
	}
	if extra := tokExtraJSON(tok); len(extra) > 0 {
		out["extra"] = extra
	}

	sa, err := NewServerAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := []byte(tok.AccessToken)
	lenBuf := []byte{byte(len(at) >> 8), byte(len(at))}
	err = sa.Authenticate(ctx, bytes.NewBuffer(append(lenBuf, at...)))
	if err != nil {
		t.Fatal(err)
	}
}

func tokExtraJSON(tok *oauth2.Token) map[string]any {
	keys := []string{"expires_in", "scope"}
	m := make(map[string]any)
	for _, k := range keys {
		if v := tok.Extra(k); v != nil {
			m[k] = v
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
