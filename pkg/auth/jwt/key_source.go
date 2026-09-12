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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeySource defines an interface for loading JWK sets.
type KeySource interface {
	LoadKeys(ctx context.Context) (jwk.Set, error)
}

// FileKeySource loads a single PEM-encoded public key.
type FileKeySource struct {
	Path string
}

// JWKSFileSource loads JWKS from a local JSON file.
type JWKSFileSource struct {
	Path string
}

// JWKSURLSource loads JWKS from a remote URL.
type JWKSURLSource struct {
	Url string
}

// LoadKeys loads a PEM file and converts it to a JWK set.
func (s *FileKeySource) LoadKeys(ctx context.Context) (jwk.Set, error) {
	// Read public key file
	keyData, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Create a new key set
	set := jwk.NewSet()

	// Process each PEM block in the file
	var block *pem.Block
	rest := keyData
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		// Skip non-public key blocks
		if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
			continue
		}

		// Parse public key
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		// Import the public key as a JWK
		k, err := jwk.Import(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWK: %w", err)
		}

		// Compute and set the key ID (thumbprint)
		thumbprint, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to compute key thumbprint: %w", err)
		}

		if err := k.Set(jwk.KeyIDKey, string(thumbprint)); err != nil {
			return nil, fmt.Errorf("failed to set key ID: %w", err)
		}

		if err := set.AddKey(k); err != nil {
			return nil, fmt.Errorf("failed to add key to set: %w", err)
		}

		// If no more PEM blocks, we're done
		if len(rest) == 0 {
			break
		}
	}

	// Ensure we found at least one valid key
	if set.Len() == 0 {
		return nil, fmt.Errorf("%w: no valid public keys found in file", ErrInvalidKey)
	}

	return set, nil
}

// LoadKeys loads JWKS from a local JSON file.
func (s *JWKSFileSource) LoadKeys(ctx context.Context) (jwk.Set, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS file: %w", err)
	}

	set, err := jwk.ParseString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return set, nil
}

// LoadKeys fetches JWKS from a remote URL.
func (s *JWKSURLSource) LoadKeys(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.Url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	set, err := jwk.ParseString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return set, nil
}

// GetKey returns the appropriate key for token verification from a JWK set.
func GetKey(set jwk.Set, token *jwt.Token) (any, error) {
	var (
		kid string
		key jwk.Key
		err error
	)

	// Get key ID from token header
	kid, _ = token.Header["kid"].(string)

	key, _ = set.Key(0)
	if set.Len() > 1 && kid != "" {
		// If kid is specified, look for that specific key
		key, _ = set.LookupKeyID(kid)
	}

	if key == nil {
		return nil, ErrNoValidKey
	}

	// Extract the raw key material
	var rawKey any
	if err = jwk.Export(key, &rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	return rawKey, nil
}
