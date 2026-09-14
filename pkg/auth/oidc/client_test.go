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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func unsignedJWTWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(hdr) + "." + enc(body) + "."
}

func TestRequireIDTokenNonce(t *testing.T) {
	raw := unsignedJWTWithClaims(t, map[string]any{"nonce": "abc", "sub": "u1"})
	if err := requireIDTokenNonce(raw, "abc"); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if err := requireIDTokenNonce(raw, "xyz"); err != ErrNonceMismatch {
		t.Fatalf("want ErrNonceMismatch, got %v", err)
	}
	missing := unsignedJWTWithClaims(t, map[string]any{"sub": "u1"})
	if err := requireIDTokenNonce(missing, "abc"); err == nil || !strings.Contains(err.Error(), "missing nonce") {
		t.Fatalf("want missing nonce error, got %v", err)
	}
}
