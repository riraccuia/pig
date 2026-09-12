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
	defaultScopes       = "openid profile email"
)

// Config is the single configuration object for NewClientAuthenticator and NewServerAuthenticator.
// Fields apply to client, server, or both as documented on each field.
type Config struct {
	// IssuerURL is the OIDC issuer (e.g. IssuerGoogle). Required for client and server.
	IssuerURL string

	// ClientID is the OAuth 2.0 client identifier. Required for client and server (audience checks).
	ClientID string

	// ClientSecret is optional; leave empty for public clients using PKCE.
	ClientSecret string

	// Scopes for the authorization request. If nil or empty, defaults to openid, profile, email.
	Scopes []string

	// RedirectURL is the full OAuth redirect URI registered at the IdP.
	// If empty, the client listens on 127.0.0.1:ephemeral-port and uses
	// http://127.0.0.1:<port><RedirectPath>. That URI must be registered:
	// e.g. Google Cloud Console OAuth client (Desktop) → Authorized redirect URIs,
	// including each loopback URL if you fix the port, or patterns your client type allows.
	// If non-empty, the host must be 127.0.0.1 or localhost with an explicit port; scheme may be
	// http or https. For https, the local callback uses a short-lived cert from certificate.GenerateCertificate.
	RedirectURL string

	// RedirectPath is the path for the loopback redirect when RedirectURL is empty (default "/oauth2/callback").
	RedirectPath string

	// HTTPClient is used for discovery, JWKS fetch, and token exchange (via oauth2 context).
	// If nil, a client with a 60s timeout per request is used.
	HTTPClient *http.Client

	// SkipOpenBrowser, if true, does not open the system browser; ErrBrowserSkipped wraps the auth URL.
	SkipOpenBrowser bool

	// CallbackTimeout bounds how long the client waits for the redirect after opening the browser.
	// Zero means default (3 minutes).
	CallbackTimeout time.Duration

	// ExpectedAudience, if non-empty, overrides ClientID when validating the id_token aud claim (server only).
	ExpectedAudience string

	// ClockSkew is leeway for exp/iat/nbf when verifying id tokens on the server,
	// and for deciding when the client should refresh an in-memory id_token before re-auth. Zero uses 30s.
	ClockSkew time.Duration

	// DisablePKCE disables PKCE (not recommended). Some confidential clients may require it off when using only client_secret.
	DisablePKCE bool

	// ClaimMatchers (server only): optional extra checks on claims after the token is accepted.
	// For an id_token, values are read from the JWT payload. Each map key is a claim name; the value must be either:
	//   - string: a regular expression matched against the claim with regexp.MatchString (not anchored; use ^...$ for full-string match).
	//   - []string or []any (string elements): the claim must equal one of these values exactly.
	// For opaque tokens (provider-specific), only claims implemented by that provider are supported
	// (e.g. GitHub: email via /user/emails; login, name, id, sub via /user — one /user call per validation).
	ClaimMatchers map[string]any
}

// ValidateForClient checks fields required for the interactive OAuth client authenticator.
func (c Config) ValidateForClient() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("oidc: IssuerURL is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("oidc: ClientID is required")
	}
	if c.RedirectPath != "" && !strings.HasPrefix(c.RedirectPath, "/") {
		return fmt.Errorf("oidc: RedirectPath must start with /")
	}
	if c.RedirectURL != "" {
		if _, err := url.Parse(c.RedirectURL); err != nil {
			return fmt.Errorf("oidc: RedirectURL: %w", err)
		}
	}
	if c.DisablePKCE && c.ClientSecret == "" {
		return fmt.Errorf("oidc: DisablePKCE with empty ClientSecret is unsafe for most providers")
	}
	return nil
}

// ValidateForServer checks fields required for id_token verification.
func (c Config) ValidateForServer() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("oidc: IssuerURL is required")
	}
	//if strings.TrimSpace(c.ClientID) == "" {
	//	return fmt.Errorf("oidc: ClientID is required")
	//}
	if _, err := parseClaimMatchers(c.ClaimMatchers); err != nil {
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

func (c *Config) clockSkew() time.Duration {
	if c.ClockSkew > 0 {
		return c.ClockSkew
	}
	return defaultClockSkew
}

func (c *Config) effectiveAudience() string {
	if strings.TrimSpace(c.ExpectedAudience) != "" {
		return strings.TrimSpace(c.ExpectedAudience)
	}
	return strings.TrimSpace(c.ClientID)
}

func (c *Config) scopeString() []string {
	if len(c.Scopes) > 0 {
		out := make([]string, 0, len(c.Scopes))
		for _, s := range c.Scopes {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return strings.Fields(defaultScopes)
}

// BrowserSkippedError wraps ErrBrowserSkipped with the authorization URL the user must open.
type BrowserSkippedError struct {
	AuthURL string
}

func (e *BrowserSkippedError) Error() string {
	return fmt.Sprintf("%v: %s", ErrBrowserSkipped, e.AuthURL)
}
