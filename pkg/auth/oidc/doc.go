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
// Client: wraps pkg/auth/oauth authorization code flow with a nonce on the authorization request,
// requires an id_token (and matching nonce after the code flow), and writes it on the connection
// using the same 2-byte length prefix + payload framing as pkg/auth/jwt.
//
// Server: reads a framed JWT id_token and verifies it (issuer, JWKS, aud, exp, etc.).
// Optional ClaimMatchers apply additional constraints to JWT claims. The listen side does not
// check nonce (it was not party to the authorization request).
package oidc
