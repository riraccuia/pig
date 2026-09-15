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
	"strings"
	"time"

	"github.com/riraccuia/pig/pkg/auth/oauth"
)

const defaultScopes = "openid profile email"

// Config embeds OAuth settings. OIDC-specific behavior (discovery, id_token, scopes) lives in this package;
// shared server fields such as ExpectedAudience and ClockSkew are on oauth.Config.
type Config struct {
	oauth.Config
}

// ValidateForClient checks fields required for the interactive OIDC client authenticator.
func (c Config) ValidateForClient() error {
	return c.Config.ValidateForClient()
}

// ValidateForServer checks fields required for id_token verification.
func (c Config) ValidateForServer() error {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return fmt.Errorf("oidc: IssuerURL is required")
	}
	if _, err := oauth.ParseClaimMatchers(c.ClaimMatchers); err != nil {
		return err
	}
	return nil
}

func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// withClientScopes returns a copy with OIDC client scopes applied: empty defaults to
// openid profile email, and openid is prepended when missing from an explicit list.
func (c Config) withClientScopes() Config {
	out := c
	if len(out.Scopes) == 0 {
		out.Scopes = strings.Fields(defaultScopes)
		return out
	}
	scopes := make([]string, 0, len(out.Scopes)+1)
	hasOpenID := false
	for _, s := range out.Scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s == "openid" {
			hasOpenID = true
		}
		scopes = append(scopes, s)
	}
	if len(scopes) == 0 {
		out.Scopes = strings.Fields(defaultScopes)
		return out
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	out.Scopes = scopes
	return out
}
