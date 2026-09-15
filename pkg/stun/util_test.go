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
	"unicode"
)

func TestOpaqueString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "plain ASCII unchanged",
			input:    "password123",
			expected: "password123",
		},
		{
			name:     "NFC normalization",
			input:    "e\u0301", // e + combining acute accent
			expected: "é",       // NFC precomposed
		},
		{
			name:     "multiple non-ASCII spaces",
			input:    "a\u00a0b\u00a0c", // U+00A0 NO-BREAK SPACE
			expected: "a b c",
		},
		{
			name:     "control characters are disallowed",
			input:    "my cat is a	by",
			expected: "my cat is a by",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OpaqueString(tt.input)
			if got != tt.expected {
				t.Errorf("OpaqueString(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestOpaqueStringMapsZsCategoryToSpace verifies that all Unicode Zs (Space_Separator)
// category runes are mapped to ASCII space (U+0020) per RFC 8265.
func TestOpaqueStringMapsZsCategoryToSpace(t *testing.T) {
	iter := func(lo, hi, stride uint32) {
		for c := lo; c <= hi; c += stride {
			r := rune(c)
			got := OpaqueString(string(r))
			if got != " " {
				t.Errorf("Zs rune U+%04X: OpaqueString(%q) = %q, want \" \"", r, string(r), got)
			}
		}
	}
	for _, r16 := range unicode.Zs.R16 {
		iter(uint32(r16.Lo), uint32(r16.Hi), uint32(r16.Stride))
	}
}
