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
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// calculatePadding returns the number of bytes needed to align the given length to 4 bytes.
// STUN attributes must be padded to a multiple of 4 bytes per RFC 5389.
func calculatePadding(length int) int {
	if length%4 == 0 {
		return 0
	}
	return 4 - (length % 4)
}

// OpaqueString converts a string to an OpaqueString according to RFC 8265.
// RFC 8489 mandates the use of the OpaqueString profile for the HMAC-SHA1 key calculation and
// also the USERNAME, USERHASH and REALM attributes.
// The OpaqueString profile is defined in RFC 8265 section 4.2.  The encoding used is UTF-8 (RFC 3629).
func OpaqueString(s string) string {
	/*
			1.  Width Mapping Rule: Fullwidth and halfwidth code points MUST NOT
		       be mapped to their decomposition mappings (see Unicode Standard
		       Annex #11 [UAX11]).

		   2.  Additional Mapping Rule: Any instances of non-ASCII space MUST be
		       mapped to SPACE (U+0020); a non-ASCII space is any Unicode code
		       point having a Unicode general category of "Zs", with the
		       exception of SPACE (U+0020).  As was the case in RFC 4013, the
		       inclusion of only SPACE (U+0020) prevents confusion with various
		       non-ASCII space code points, many of which are difficult to
		       reproduce across different input methods.

		   3.  Case Mapping Rule: There is no case mapping rule (because mapping
		       uppercase and titlecase code points to their lowercase
		       equivalents would lead to false accepts and thus to reduced
		       security).

		   4.  Normalization Rule: Unicode Normalization Form C (NFC) MUST be
		       applied to all strings.

		   5.  Directionality Rule: There is no directionality rule.  The "Bidi
		       Rule" (defined in [RFC5893]) and similar rules are unnecessary
		       and inapplicable to passwords, because they can reduce the
		       repertoire of characters that are allowed in a string and
		       therefore reduce the amount of entropy that is possible in a
		       password.  Such rules are intended to minimize the possibility
		       that the same string will be displayed differently on a layout
		       system set for right-to-left display and a layout system set for
		       left-to-right display; however, passwords are typically not
		       displayed at all and are rarely meant to be interoperable across
		       different layout systems in the way that non-secret strings like
		       domain names and usernames are.  Furthermore, it is perfectly
		       acceptable for opaque strings other than passwords to be
		       presented differently in different layout systems, as long as the
		       presentation is consistent in any given layout system.
	*/

	stringBuilder := strings.Builder{}

	// map non-ASCII space to SPACE (U+0020)
	for i, w := 0, 0; i < len(s); i += w {
		r, width := utf8.DecodeRuneInString(s[i:])
		w = width
		if !unicode.IsSpace(r) {
			stringBuilder.WriteRune(r)
			continue
		}
		stringBuilder.WriteRune('\u0020') // U+0020 SPACE
	}

	// normalize the password using NFC
	normalizedString := norm.NFC.String(stringBuilder.String())

	return normalizedString
}
