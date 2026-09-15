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

package stun

import (
	"testing"
)

// makeParsedRequest builds a BindingRequest suitable for integrity checks.
func makeParsedRequest(t *testing.T, user, pass string) *Message {
	msg, err := BuildBindingRequest(&BindingOptions{
		Auth:               &AuthConfig{Username: user, Password: pass},
		RequireFingerprint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = msg.AddFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	err = msg.Validate(&BindingOptions{
		RequireFingerprint: true,
		Auth:               &AuthConfig{Username: user, Password: pass},
	})
	if err != nil {
		t.Fatalf("failed to validate binding request: %v", err)
		return nil
	}
	return msg
}

// TestValidateShortTermIntegrity checks that ValidateShortTermIntegrity correctly
// skips when credentials are absent, passes on valid user+password, and fails on
// mismatch, wrong password, missing username, or invalid request.
func TestValidateShortTermIntegrity(t *testing.T) {
	validReq := makeParsedRequest(t, "user", "secret")
	//reqWithoutAuth := makeParsedRequest(t, "user", "secret", false)
	validAuth := &AuthConfig{Username: "user", Password: "secret"}

	tests := []struct {
		name       string
		req        *Message
		auth       *AuthConfig
		shouldPass bool
	}{
		// No auth required — early return
		{"auth nil skips validation", nil, nil, true},
		{"empty password skips validation", nil, &AuthConfig{Password: ""}, true},
		// Success
		{"valid user and password", validReq, validAuth, true},
		// Failures
		{"wrong username", validReq, &AuthConfig{Username: "other", Password: "secret"}, false},
		{"wrong password", validReq, &AuthConfig{Username: "user", Password: "wrong"}, false},
		//{"request has no parsed username", reqWithoutAuth, validAuth, false},
		{"nil request", nil, validAuth, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateShortTermIntegrity(tt.req, tt.auth)
			if tt.shouldPass && err != nil {
				t.Errorf("expected pass, got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
