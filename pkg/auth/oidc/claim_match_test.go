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
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

func TestParseClaimMatchersInvalidRegex(t *testing.T) {
	_, err := parseClaimMatchers(map[string]any{"email": "["})
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
}

func TestParseClaimMatchersInvalidListElement(t *testing.T) {
	_, err := parseClaimMatchers(map[string]any{"role": []any{42}})
	if err == nil {
		t.Fatal("expected error for non-string list element")
	}
}

func TestParseClaimMatchersOK(t *testing.T) {
	rules, err := parseClaimMatchers(map[string]any{
		"email":  `user@host`,
		"org_id": []string{"x", "y"},
		"role":   []any{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("len=%d want 3", len(rules))
	}
}

func TestValidateJWTClaimRules(t *testing.T) {
	claims := jwtgo.MapClaims{
		"email": "user@host.example",
		"multi": []any{"nope", "yes"},
		"num":   float64(42),
	}
	rules, err := parseClaimMatchers(map[string]any{
		"email": `@host\.`,
		"multi": []string{"yes"},
		"num":   []string{"42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateJWTClaimRules(claims, rules); err != nil {
		t.Fatal(err)
	}

	rules2, err := parseClaimMatchers(map[string]any{"email": []string{"other"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateJWTClaimRules(claims, rules2); err == nil {
		t.Fatal("expected rejection")
	}
}
