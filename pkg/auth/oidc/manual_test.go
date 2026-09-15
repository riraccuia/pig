//go:build manual

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v5"
)

func TestManualGoogleOIDCClientFlow(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		IssuerURL:    "https://accounts.google.com",
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		Scopes:       []string{"openid", "email", "profile"},
		//RedirectURL:     "http://127.0.0.1:12345/oauth2/callback",
		ClaimMatchers: map[string]any{
			"email": []string{"something@example.com", "your-email@example.com"},
		},
	}

	ca, err := NewClientAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = ca.Authenticate(ctx, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}

	tok := ca.(*ClientAuthenticator).idTok

	tokParsed, _, err := jwtgo.NewParser().ParseUnverified(tok, &jwtgo.MapClaims{})
	if err != nil {
		t.Errorf("Error parsing token: %s ", err.Error())
		return
	}

	jsonBytes, err := json.MarshalIndent(tokParsed.Claims, "", "  ")
	if err != nil {
		t.Errorf("Error marshalling JSON: %s ", err.Error())
		return
	}
	t.Log(string(jsonBytes))

	out := map[string]any{
		"id_token": tok,
	}

	jsonBytes, err = json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Errorf("Error marshalling JSON: %s ", err.Error())
		return
	}
	t.Log(string(jsonBytes))

	sa, err := NewServerAuthenticator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := []byte(tok)
	lenBuf := []byte{byte(len(at) >> 8), byte(len(at))}
	err = sa.Authenticate(ctx, bytes.NewBuffer(append(lenBuf, at...)))
	if err != nil {
		t.Fatal(err)
	}
}
