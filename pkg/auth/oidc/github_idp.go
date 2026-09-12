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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// IssuerGitHub is the base URL used to fetch OpenID discovery at
// https://github.com/login/oauth/.well-known/openid-configuration.
// The document's issuer claim and ID tokens use https://github.com (see githubDiscoveryIssuer and patchGitHubProviderMetadataIfNeeded).
const IssuerGitHub = "https://github.com/login/oauth"

const (
	// GitHub's openid-configuration omits authorization_endpoint and token_endpoint.
	// OAuth 2.0 endpoints: https://docs.github.com/en/apps/oauth-apps
	githubDiscoveryIssuer       = "https://github.com"
	githubAuthorizationEndpoint = "https://github.com/login/oauth/authorize"
	githubTokenEndpoint         = "https://github.com/login/oauth/access_token"
	githubJWKSPathPrefix        = "https://github.com/login/oauth"

	// GitHub REST API (authenticated user).
	githubAPIUserEmailsURL = "https://api.github.com/user/emails"
	githubAPIUserURL       = "https://api.github.com/user"
)

func githubConfigIssuerMatchesDocIssuer(cfgIss, docIss string) bool {
	return docIss == githubDiscoveryIssuer && cfgIss == NormalizeIssuer(IssuerGitHub)
}

// patchGitHubProviderMetadataIfNeeded fills OAuth endpoints when the discovery document looks like GitHub's but omits them.
func patchGitHubProviderMetadataIfNeeded(meta *ProviderMetadata) {
	if meta == nil {
		return
	}
	iss := NormalizeIssuer(meta.Issuer)
	jwks := strings.TrimSpace(meta.JWKSURI)
	if iss != githubDiscoveryIssuer && !strings.HasPrefix(jwks, githubJWKSPathPrefix) {
		return
	}
	if meta.AuthorizationEndpoint == "" {
		meta.AuthorizationEndpoint = githubAuthorizationEndpoint
	}
	if meta.TokenEndpoint == "" {
		meta.TokenEndpoint = githubTokenEndpoint
	}
}

// providerSupportsOpaqueTokenFallback reports whether the client may send an OAuth access_token on the wire when
// no id_token is present, and the server may verify it with GitHub-specific logic.
func providerSupportsOpaqueTokenFallback(cfg Config, meta *ProviderMetadata) bool {
	if meta == nil {
		return false
	}
	cfgIss := NormalizeIssuer(cfg.IssuerURL)
	docIss := NormalizeIssuer(meta.Issuer)
	if !issuerMatchesDiscovery(cfgIss, docIss) {
		return false
	}
	jwks := strings.TrimSpace(meta.JWKSURI)
	return docIss == githubDiscoveryIssuer || strings.HasPrefix(jwks, githubJWKSPathPrefix)
}

type githubOpaqueVerifier struct{}

func (githubOpaqueVerifier) verifyOpaque(ctx context.Context, hc *http.Client, token string, rules []claimRule) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	if len(rules) == 0 {
		return verifyGitHubHasVerifiedPrimaryEmail(ctx, hc, token)
	}
	var cache githubAPIClaimCache
	return validateClaimRulesStringValues(rules, func(claim string) ([]string, bool, error) {
		return cache.resolveClaimValues(ctx, hc, token, claim)
	})
}

func verifyGitHubHasVerifiedPrimaryEmail(ctx context.Context, hc *http.Client, token string) error {
	entries, err := fetchGitHubUserEmails(ctx, hc, token)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Primary {
			continue
		}
		if !e.Verified {
			return fmt.Errorf("%w: github primary email is not verified", ErrInvalidToken)
		}
		if strings.TrimSpace(e.Email) != "" {
			return nil
		}
		break
	}
	return fmt.Errorf("%w: no verified primary email from github", ErrInvalidToken)
}

type githubEmailEntry struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubAPIGetJSON performs an authorized GET to the GitHub API and decodes JSON into dest.
func githubAPIGetJSON(ctx context.Context, hc *http.Client, token, reqURL, apiLabel string, dest any) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "qt-oidc-server")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: github %s: %w", apiLabel, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: github %s: %s: %s", ErrInvalidToken, apiLabel, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("%w: github %s JSON: %v", ErrInvalidToken, apiLabel, err)
	}
	return nil
}

func fetchGitHubUserEmails(ctx context.Context, hc *http.Client, token string) ([]githubEmailEntry, error) {
	var entries []githubEmailEntry
	if err := githubAPIGetJSON(ctx, hc, token, githubAPIUserEmailsURL, "user/emails", &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

type githubUserPayload struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

func fetchGitHubUser(ctx context.Context, hc *http.Client, token string) (*githubUserPayload, error) {
	var u githubUserPayload
	if err := githubAPIGetJSON(ctx, hc, token, githubAPIUserURL, "user", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// githubAPIClaimCache lazily loads GitHub REST responses for opaque claim_matchers.
// At most one GET /user and one GET /user/emails run per validation round.
type githubAPIClaimCache struct {
	emails        []githubEmailEntry
	user          *githubUserPayload
	emailsFetched bool
	userFetched   bool
}

func (c *githubAPIClaimCache) ensureUser(ctx context.Context, hc *http.Client, token string) error {
	if c.userFetched {
		return nil
	}
	u, err := fetchGitHubUser(ctx, hc, token)
	if err != nil {
		return err
	}
	c.user = u
	c.userFetched = true
	return nil
}

// resolveClaimValues loads (with caching per githubAPIClaimCache) the string values for a single ClaimMatchers
// key when authenticating a GitHub OAuth access token. It maps claim names to GitHub REST resources:
// "email" from /user/emails (verified addresses only), and "login", "name", "id", "sub" from /user.
//
// Returns:
//   - values: candidates passed to regex or exact matching; typically one entry per field, or multiple for email.
//   - ok: false if the claim has no usable values (missing field, no verified emails, etc.); true if values is non-empty.
//   - err: non-nil for unsupported claim names or HTTP/API failures.
func (c *githubAPIClaimCache) resolveClaimValues(ctx context.Context, hc *http.Client, token, claim string) ([]string, bool, error) {
	switch strings.TrimSpace(claim) {
	case "email":
		if !c.emailsFetched {
			e, err := fetchGitHubUserEmails(ctx, hc, token)
			if err != nil {
				return nil, false, err
			}
			c.emails = e
			c.emailsFetched = true
		}
		var out []string
		for _, e := range c.emails {
			if !e.Verified {
				continue
			}
			if em := strings.TrimSpace(e.Email); em != "" {
				out = append(out, em)
			}
		}
		if len(out) == 0 {
			return nil, false, nil
		}
		return out, true, nil
	case "login":
		if err := c.ensureUser(ctx, hc, token); err != nil {
			return nil, false, err
		}
		if c.user == nil || strings.TrimSpace(c.user.Login) == "" {
			return nil, false, nil
		}
		return []string{c.user.Login}, true, nil
	case "name":
		if err := c.ensureUser(ctx, hc, token); err != nil {
			return nil, false, err
		}
		if c.user == nil || strings.TrimSpace(c.user.Name) == "" {
			return nil, false, nil
		}
		return []string{strings.TrimSpace(c.user.Name)}, true, nil
	case "id", "sub":
		if err := c.ensureUser(ctx, hc, token); err != nil {
			return nil, false, err
		}
		if c.user == nil {
			return nil, false, nil
		}
		return []string{strconv.FormatInt(c.user.ID, 10)}, true, nil
	default:
		return nil, false, fmt.Errorf("%w: github opaque: unsupported claim %q for claim_matchers", ErrInvalidToken, claim)
	}
}
