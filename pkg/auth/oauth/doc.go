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

// Package oauth implements OAuth 2.0 authenticators that satisfy common.Authenticator.
//
// Client: runs an OAuth 2.0 authorization code flow with PKCE by default, opens the system browser,
// and writes the OAuth access_token on the connection using the same 2-byte length prefix + payload
// framing as pkg/auth/jwt. Providers that also return an id_token leave it in oauth2.Token Extra for
// OIDC callers; this package does not interpret or send id_token.
//
// Server: reads a framed access token and validates it with, in order: provider-specific opaque logic
// (for example GitHub REST), or JWT verification via discovery jwks_uri when the token looks like a JWT.
// Optional Config.ClaimMatchers apply additional constraints after the token is accepted.
package oauth
