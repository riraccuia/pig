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
	"strings"

	"github.com/riraccuia/pig/pkg/auth/oauth"
)

// ProviderMetadata holds the subset of OpenID Provider Metadata used by this package.
type ProviderMetadata = oauth.ProviderMetadata

// NormalizeIssuer trims space and removes a trailing slash from the configured issuer.
func NormalizeIssuer(issuer string) string {
	return oauth.NormalizeIssuer(issuer)
}

func wellKnownURL(issuer string) string {
	return NormalizeIssuer(issuer) + "/.well-known/openid-configuration"
}

func validateProviderMetadata(meta *ProviderMetadata) error {
	if meta.Issuer == "" {
		return fmt.Errorf("oidc discovery: missing issuer")
	}
	if meta.AuthorizationEndpoint == "" {
		return fmt.Errorf("oidc discovery: missing authorization_endpoint")
	}
	if meta.TokenEndpoint == "" {
		return fmt.Errorf("oidc discovery: missing token_endpoint")
	}
	if meta.JWKSURI == "" {
		return fmt.Errorf("oidc discovery: missing jwks_uri")
	}
	return nil
}

func issuerMatchesDiscovery(cfgIss, docIss string) bool {
	return cfgIss == docIss
}

// fetchProviderMetadata loads OpenID Provider Metadata from the issuer's well-known URL.
func fetchProviderMetadata(ctx context.Context, client *http.Client, issuer string) (*ProviderMetadata, error) {
	if client == nil {
		client = http.DefaultClient
	}
	url := wellKnownURL(issuer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("oidc discovery %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var meta ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("oidc discovery decode: %w", err)
	}
	if err := validateProviderMetadata(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
