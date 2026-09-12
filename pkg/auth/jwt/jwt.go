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

package jwt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/riraccuia/pig/pkg/common"
)

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrInvalidKey     = errors.New("invalid key")
	ErrUnsupportedAlg = errors.New("unsupported signing algorithm")
	ErrNoValidKey     = errors.New("no valid key found")
)

// supportedAlgorithms maps JWT 'alg' values to their validation functions.
var supportedAlgorithms = map[string]func(token *jwt.Token) bool{
	"RS256": isRSA,
	"RS384": isRSA,
	"RS512": isRSA,
	"EdDSA": isEdDSA,
}

func isRSA(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodRSA)
	return ok
}

func isEdDSA(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodEd25519)
	return ok
}

// ServerAuthenticator implements JWT token authentication.
type ServerAuthenticator struct {
	keySet jwk.Set
}

// ClientAuthenticator implements client-side JWT token authentication.
type ClientAuthenticator struct {
	token string
}

// NewClientAuthenticator creates a new ClientAuthenticator instance.
func NewClientAuthenticator(token string) (common.Authenticator, error) {
	return &ClientAuthenticator{
		token: token,
	}, nil
}

// Authenticate sends the JWT token to the server.
func (a *ClientAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	return SendToken(rw, a.token)
}

// NewServerAuthenticator creates a new JWTAuthenticator instance.
func NewServerAuthenticator(source string) (common.Authenticator, error) {
	var keySource KeySource

	// Determine the type of source based on the string format/content
	switch {
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		keySource = &JWKSURLSource{Url: source}
	case strings.HasSuffix(source, ".json"):
		keySource = &JWKSFileSource{Path: source}
	default:
		keySource = &FileKeySource{Path: source}
	}

	// Load initial keys
	keySet, err := keySource.LoadKeys(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	return &ServerAuthenticator{
		keySet: keySet,
	}, nil
}

// validateSigningMethod checks if the token's signing method is supported.
func validateSigningMethod(token *jwt.Token) error {
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("%w: missing or invalid 'alg' header", ErrInvalidToken)
	}

	validator, supported := supportedAlgorithms[alg]
	if !supported {
		return fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}

	if !validator(token) {
		return fmt.Errorf("%w: token signing method does not match algorithm", ErrInvalidToken)
	}

	return nil
}

// Authenticate performs JWT token authentication.
func (a *ServerAuthenticator) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	// Read token length (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(rw, lenBuf); err != nil {
		return fmt.Errorf("failed to read token length: %w", err)
	}
	tokenLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// Read token
	tokenBuf := make([]byte, tokenLen)
	if _, err := io.ReadFull(rw, tokenBuf); err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}

	// Decode base64url token
	tokenStr := string(tokenBuf)

	// Parse and validate token with standard validation
	var claims jwt.MapClaims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if err := validateSigningMethod(token); err != nil {
			return nil, err
		}

		// Get the appropriate key for verification
		return GetKey(a.keySet, token)
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "EdDSA"}),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired())

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	return nil
}

// SendToken sends a JWT token over the connection.
func SendToken(rw io.ReadWriter, token string) error {
	// Convert token to bytes
	tokenBytes := []byte(token)
	tokenLen := len(tokenBytes)

	// Write token length (2 bytes)
	lenBuf := []byte{byte(tokenLen >> 8), byte(tokenLen)}
	if _, err := rw.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	// Write token
	if _, err := rw.Write(tokenBytes); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}

	return nil
}
