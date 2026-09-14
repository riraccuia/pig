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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultRedirectPath = "/oauth2/callback"
	defaultCallbackWait = 3 * time.Minute
	defaultClockSkew    = 30 * time.Second
)

// Config is the configuration object for NewClientAuthenticator and NewServerAuthenticator.
// Fields apply to client, server, or both as documented on each field.
type Config struct {
	// IssuerURL is the OAuth authorization server issuer. Required for client and server.
	IssuerURL string

	// ClientID is the OAuth 2.0 client identifier. Required for client.
	ClientID string

	// ClientSecret is optional; leave empty for public clients using PKCE.
	ClientSecret string

	// Scopes for the authorization request. If nil or empty, no scope parameter is sent.
	Scopes []string

	// RedirectURL is the full OAuth redirect URI registered at the IdP.
	// If empty, the client listens on 127.0.0.1:ephemeral-port and uses
	// http://127.0.0.1:<port><RedirectPath>. That URI must be registered.
	// If non-empty, the host must be 127.0.0.1 or localhost with an explicit port; scheme may be
	// http or https. For https, the local callback uses a short-lived cert from certificate.GenerateCertificate.
	RedirectURL string

	// RedirectPath is the path for the loopback redirect when RedirectURL is empty (default "/oauth2/callback").
	RedirectPath string

	// HTTPClient is used for discovery and token exchange (via oauth2 context).
	// If nil, a client with a 60s timeout per request is used.
	HTTPClient *http.Client

	// SkipOpenBrowser, if true, does not open the system browser; ErrBrowserSkipped wraps the auth URL.
	SkipOpenBrowser bool

	// CallbackTimeout bounds how long the client waits for the redirect after opening the browser.
	// Zero means default (3 minutes).
	CallbackTimeout time.Duration

	// DisablePKCE disables PKCE (not recommended). Some confidential clients may require it off when using only client_secret.
	DisablePKCE bool

	// ExpectedAudience, if non-empty, overrides ClientID when validating JWT aud on the server
	// (OAuth access tokens; OIDC id_tokens when this config is embedded).
	ExpectedAudience string

	// ClockSkew is leeway for exp/iat/nbf when verifying JWTs on the server.
	// Zero uses 30s.
	ClockSkew time.Duration

	// ClaimMatchers (server only): optional extra checks on claims after the token is accepted.
	// For opaque tokens (provider-specific), only claims implemented by that provider are supported
	// (e.g. GitHub: email via /user/emails; login, name, id, sub via /user — one /user call per validation).
	// For JWT access tokens, matchers run against JWT claims.
	ClaimMatchers map[string]any
}

// ValidateForClient checks fields required for the interactive OAuth client authenticator.
func (c Config) ValidateForClient() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("oauth: IssuerURL is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("oauth: ClientID is required")
	}
	if c.RedirectPath != "" && !strings.HasPrefix(c.RedirectPath, "/") {
		return fmt.Errorf("oauth: RedirectPath must start with /")
	}
	if c.RedirectURL != "" {
		if _, err := url.Parse(c.RedirectURL); err != nil {
			return fmt.Errorf("oauth: RedirectURL: %w", err)
		}
	}
	if c.DisablePKCE && c.ClientSecret == "" {
		return fmt.Errorf("oauth: DisablePKCE with empty ClientSecret is unsafe for most providers")
	}
	return nil
}

// ValidateForServer checks fields required for access token verification.
func (c Config) ValidateForServer() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("oauth: IssuerURL is required")
	}
	if _, err := ParseClaimMatchers(c.ClaimMatchers); err != nil {
		return err
	}
	return nil
}

func (c *Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Config) redirectPath() string {
	if strings.TrimSpace(c.RedirectPath) == "" {
		return defaultRedirectPath
	}
	return c.RedirectPath
}

func (c *Config) callbackTimeout() time.Duration {
	if c.CallbackTimeout > 0 {
		return c.CallbackTimeout
	}
	return defaultCallbackWait
}

func (c *Config) scopeString() []string {
	if len(c.Scopes) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Scopes))
	for _, s := range c.Scopes {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// EffectiveAudience returns ExpectedAudience if set, otherwise ClientID.
func (c Config) EffectiveAudience() string {
	if strings.TrimSpace(c.ExpectedAudience) != "" {
		return strings.TrimSpace(c.ExpectedAudience)
	}
	return strings.TrimSpace(c.ClientID)
}

// ClockSkewOrDefault returns ClockSkew, or 30s when ClockSkew is zero.
func (c Config) ClockSkewOrDefault() time.Duration {
	if c.ClockSkew > 0 {
		return c.ClockSkew
	}
	return defaultClockSkew
}

// BrowserSkippedError wraps ErrBrowserSkipped with the authorization URL the user must open.
type BrowserSkippedError struct {
	AuthURL string
}

func (e *BrowserSkippedError) Error() string {
	return fmt.Sprintf("%v: %s", ErrBrowserSkipped, e.AuthURL)
}
