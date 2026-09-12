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

import "strings"

// IssuerGitHub is in github_idp.go with the rest of the GitHub IdP implementation.

const (
	// IssuerGoogle is the Google OIDC issuer (accounts).
	IssuerGoogle = "https://accounts.google.com"

	// IssuerOktaDefaultAuthorizationServer is the usual custom authorization server ID
	// for Okta's "default" server.
	IssuerOktaDefaultAuthorizationServer = "default"
)

// OktaIssuerURL returns the OIDC issuer URL for an Okta org's default custom authorization server.
// orgBaseURL is the org base (e.g. https://dev-12345.okta.com) with no trailing slash.
func OktaIssuerURL(orgBaseURL string) string {
	base := strings.TrimSuffix(strings.TrimSpace(orgBaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/oauth2/" + IssuerOktaDefaultAuthorizationServer
}
