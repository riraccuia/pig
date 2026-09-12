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
	"fmt"
	"regexp"
	"strings"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

// claimRule is one configured constraint: claim name + how to match values.
type claimRule struct {
	claim string
	m     claimMatcher
}

type claimMatcher interface {
	Match(value string) bool
}

type regexMatcher struct {
	re *regexp.Regexp
}

func (m regexMatcher) Match(v string) bool { return m.re.MatchString(v) }

type exactMatcher struct {
	vals map[string]struct{}
}

func newExactMatcher(values []string) exactMatcher {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return exactMatcher{vals: m}
}

func (m exactMatcher) Match(v string) bool {
	_, ok := m.vals[v]
	return ok
}

func parseClaimMatchers(raw map[string]any) ([]claimRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	rules := make([]claimRule, 0, len(raw))
	for claim, val := range raw {
		claim = strings.TrimSpace(claim)
		if claim == "" {
			return nil, fmt.Errorf("oidc: claim_matchers: empty claim name")
		}
		m, err := parseClaimMatcherValue(val)
		if err != nil {
			return nil, fmt.Errorf("oidc: claim_matchers[%q]: %w", claim, err)
		}
		rules = append(rules, claimRule{claim: claim, m: m})
	}
	return rules, nil
}

func parseClaimMatcherValue(val any) (claimMatcher, error) {
	switch v := val.(type) {
	case string:
		pat := strings.TrimSpace(v)
		if pat == "" {
			return nil, fmt.Errorf("empty regex pattern")
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("regex: %w", err)
		}
		return regexMatcher{re: re}, nil
	case []string:
		if len(v) == 0 {
			return nil, fmt.Errorf("empty exact-value list")
		}
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = strings.TrimSpace(s)
			if out[i] == "" {
				return nil, fmt.Errorf("exact list element %d is empty", i)
			}
		}
		return newExactMatcher(out), nil
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("empty exact-value list")
		}
		out := make([]string, 0, len(v))
		for i, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("exact list element %d: want string, got %T", i, x)
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return nil, fmt.Errorf("exact list element %d is empty", i)
			}
			out = append(out, s)
		}
		return newExactMatcher(out), nil
	default:
		return nil, fmt.Errorf("want string (regex) or []string / []any (exact values), got %T", val)
	}
}

func extractJWTClaimStrings(claims jwtgo.MapClaims, key string) ([]string, bool) {
	raw, ok := claims[key]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case string:
		return []string{v}, true
	case []string:
		if len(v) == 0 {
			return nil, true
		}
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
				continue
			}
			out = append(out, fmt.Sprint(x))
		}
		if len(out) == 0 {
			return nil, true
		}
		return out, true
	case float64:
		return []string{fmtNumClaim(v)}, true
	case nil:
		return nil, true
	default:
		return []string{fmt.Sprint(v)}, true
	}
}

func fmtNumClaim(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%g", f)
}

func validateJWTClaimRules(claims jwtgo.MapClaims, rules []claimRule) error {
	return validateClaimRules(rules, func(r claimRule) ([]string, bool, error) {
		vals, ok := extractJWTClaimStrings(claims, r.claim)
		return vals, ok, nil
	})
}

func valuesMatchRule(m claimMatcher, candidates []string) bool {
	for _, v := range candidates {
		if m.Match(v) {
			return true
		}
	}
	return false
}

func validateClaimRules(rules []claimRule, resolve func(r claimRule) ([]string, bool, error)) error {
	if len(rules) == 0 {
		return nil
	}
	for _, r := range rules {
		vals, ok, err := resolve(r)
		if err != nil {
			return err
		}
		if !ok || len(vals) == 0 {
			return fmt.Errorf("%w: missing or empty claim %q", ErrInvalidToken, r.claim)
		}
		if !valuesMatchRule(r.m, vals) {
			return fmt.Errorf("%w: claim %q rejected by claim_matchers", ErrInvalidToken, r.claim)
		}
	}
	return nil
}

func validateClaimRulesStringValues(rules []claimRule, get func(claim string) ([]string, bool, error)) error {
	return validateClaimRules(rules, func(r claimRule) ([]string, bool, error) {
		return get(r.claim)
	})
}
