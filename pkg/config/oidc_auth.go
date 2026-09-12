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

package config

import (
	"time"

	"github.com/riraccuia/pig/pkg/auth/oidc"
)

// ToConfig maps this TOML/JSON struct to pkg/auth/oidc.Config.
func (o *OIDCAuth) ToConfig() oidc.Config {
	if o == nil {
		return oidc.Config{}
	}
	cfg := oidc.Config{
		IssuerURL:        o.IssuerURL,
		ClientID:         o.ClientID,
		ClientSecret:     o.ClientSecret,
		Scopes:           o.Scopes,
		RedirectURL:      o.RedirectURL,
		RedirectPath:     o.RedirectPath,
		SkipOpenBrowser:  o.SkipOpenBrowser,
		ExpectedAudience: o.ExpectedAudience,
		DisablePKCE:      o.DisablePKCE,
		ClaimMatchers:    o.ClaimMatchers,
	}
	if o.CallbackTimeoutSeconds > 0 {
		cfg.CallbackTimeout = time.Duration(o.CallbackTimeoutSeconds) * time.Second
	}
	if o.ClockSkewSeconds > 0 {
		cfg.ClockSkew = time.Duration(o.ClockSkewSeconds) * time.Second
	}
	return cfg
}
