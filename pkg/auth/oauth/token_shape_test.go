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

import "testing"

func TestTokenLooksLikeJWT(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"a.b.c", true},
		{" header.payload.sig ", true},
		{"gho_xxxxxxxx", false},
		{"a.b", false},
		{"a.b.c.d", false},
		{".b.c", false},
		{"a..c", false},
		{"a.b.", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := tokenLooksLikeJWT(tt.in); got != tt.want {
			t.Errorf("tokenLooksLikeJWT(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
