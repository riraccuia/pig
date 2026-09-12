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

// Package oidc implements OpenID Connect authenticators that satisfy common.Authenticator.
//
// Client: runs an OAuth 2.0 authorization code flow with PKCE by default, opens the system browser,
// and writes the credential on the connection using the same 2-byte length prefix + payload framing as pkg/auth/jwt.
// When the provider returns an id_token, that JWT is sent; for configured providers (e.g. GitHub) that omit id_token,
// the OAuth access_token may be sent instead.
//
// Server: reads a framed token. Values that look like a JWT are verified as an OIDC id_token (issuer, JWKS, aud, exp, etc.).
// For supported providers, non-JWT payloads are treated as opaque access tokens and checked with provider-specific logic
// (for example GitHub REST). Optional Config.ClaimMatchers apply additional constraints (regex or exact lists) to JWT
// claims or to provider-resolved opaque claims.
package oidc
