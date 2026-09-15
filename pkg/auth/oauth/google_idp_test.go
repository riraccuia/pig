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
	"strconv"
	"testing"
	"time"
)

func TestValidateGoogleTokenInfo(t *testing.T) {
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)

	if err := validateGoogleTokenInfo(&googleTokenInfo{Exp: future, Aud: "cid"}, "cid"); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
	if err := validateGoogleTokenInfo(&googleTokenInfo{Exp: future, Azp: "cid"}, "cid"); err != nil {
		t.Fatalf("expected azp match: %v", err)
	}
	if err := validateGoogleTokenInfo(&googleTokenInfo{Exp: past, Aud: "cid"}, "cid"); err == nil {
		t.Fatal("expected expired")
	}
	if err := validateGoogleTokenInfo(&googleTokenInfo{Exp: future, Aud: "other"}, "cid"); err == nil {
		t.Fatal("expected aud mismatch")
	}
}

func TestGoogleTokenInfoClaimValues(t *testing.T) {
	info := &googleTokenInfo{
		Email:         "a@example.com",
		EmailVerified: "true",
		Sub:           "123",
		Scope:         "openid email",
	}
	vals, ok, err := googleTokenInfoClaimValues(info, "email")
	if err != nil || !ok || len(vals) != 1 || vals[0] != "a@example.com" {
		t.Fatalf("email: vals=%v ok=%v err=%v", vals, ok, err)
	}
	vals, ok, err = googleTokenInfoClaimValues(info, "scope")
	if err != nil || !ok || len(vals) != 2 {
		t.Fatalf("scope: vals=%v ok=%v err=%v", vals, ok, err)
	}
	info.EmailVerified = "false"
	_, ok, err = googleTokenInfoClaimValues(info, "email")
	if err != nil || ok {
		t.Fatalf("unverified email should be empty: ok=%v err=%v", ok, err)
	}
}
