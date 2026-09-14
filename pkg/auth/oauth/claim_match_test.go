package oauth

import (
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

func TestParseClaimMatchersInvalidRegex(t *testing.T) {
	_, err := ParseClaimMatchers(map[string]any{"email": "["})
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
}

func TestParseClaimMatchersInvalidListElement(t *testing.T) {
	_, err := ParseClaimMatchers(map[string]any{"role": []any{42}})
	if err == nil {
		t.Fatal("expected error for non-string list element")
	}
}

func TestParseClaimMatchersOK(t *testing.T) {
	rules, err := ParseClaimMatchers(map[string]any{
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
	rules, err := ParseClaimMatchers(map[string]any{
		"email": `@host\.`,
		"multi": []string{"yes"},
		"num":   []string{"42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJWTClaimRules(claims, rules); err != nil {
		t.Fatal(err)
	}

	rules2, err := ParseClaimMatchers(map[string]any{"email": []string{"other"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJWTClaimRules(claims, rules2); err == nil {
		t.Fatal("expected rejection")
	}
}
