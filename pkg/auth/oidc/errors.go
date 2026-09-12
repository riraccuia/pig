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

import "errors"

var (
	// ErrBrowserSkipped is returned when SkipOpenBrowser is true and the flow cannot proceed without manual navigation.
	ErrBrowserSkipped = errors.New("oidc: browser open skipped; open authorization URL manually")

	// ErrMissingIDToken indicates the token response did not contain id_token.
	ErrMissingIDToken = errors.New("oidc: token response missing id_token")

	// ErrInvalidState means the OAuth state parameter did not match.
	ErrInvalidState = errors.New("oidc: invalid OAuth state")

	// ErrAuthorizationDenied is returned when the provider redirects with an error (e.g. access_denied).
	ErrAuthorizationDenied = errors.New("oidc: authorization denied or error from provider")

	// ErrInvalidToken is returned when ID token verification fails.
	ErrInvalidToken = errors.New("oidc: invalid id token")
)
