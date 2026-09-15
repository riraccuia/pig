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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ProviderMetadata holds the subset of OAuth Authorization Server Metadata used by this package.
type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NormalizeIssuer trims space and removes a trailing slash from the configured issuer.
func NormalizeIssuer(issuer string) string {
	return strings.TrimSuffix(strings.TrimSpace(issuer), "/")
}

// oauthAuthorizationServerMetadataURL builds the RFC 8414 well-known URL by inserting
// /.well-known/oauth-authorization-server after the host, then the issuer path.
// Example: https://github.com/login/oauth -> https://github.com/.well-known/oauth-authorization-server/login/oauth
func oauthAuthorizationServerMetadataURL(issuer string) (string, error) {
	raw := NormalizeIssuer(issuer)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("oauth discovery: issuer URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("oauth discovery: issuer URL must include scheme and host")
	}
	path := u.Path
	if path == "/" {
		path = ""
	}
	u.Path = "/.well-known/oauth-authorization-server" + path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func validateProviderMetadata(meta *ProviderMetadata) error {
	if meta.Issuer == "" {
		return fmt.Errorf("oauth discovery: missing issuer")
	}
	if meta.AuthorizationEndpoint == "" {
		return fmt.Errorf("oauth discovery: missing authorization_endpoint")
	}
	if meta.TokenEndpoint == "" {
		return fmt.Errorf("oauth discovery: missing token_endpoint")
	}
	return nil
}

// issuerMatchesDiscovery reports whether cfg.IssuerURL is compatible with meta.Issuer from discovery.
func issuerMatchesDiscovery(cfgIss, docIss string) bool {
	return cfgIss == docIss
}

// FetchProviderMetadata loads OAuth Authorization Server Metadata from the issuer's RFC 8414 well-known URL.
func FetchProviderMetadata(ctx context.Context, client *http.Client, issuer string) (*ProviderMetadata, error) {
	if client == nil {
		client = http.DefaultClient
	}
	metaURL, err := oauthAuthorizationServerMetadataURL(issuer)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth discovery GET %s: %w", metaURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("oauth discovery %s: HTTP %d: %s", metaURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var meta ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("oauth discovery decode: %w", err)
	}
	if err := validateProviderMetadata(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
