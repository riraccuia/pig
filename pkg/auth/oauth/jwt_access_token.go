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
	"context"
	"fmt"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	authjwt "github.com/riraccuia/pig/pkg/auth/jwt"
)

func fetchJWKS(ctx context.Context, jwksURL string) (jwk.Set, error) {
	src := &authjwt.JWKSURLSource{Url: jwksURL}
	return src.LoadKeys(ctx)
}

func audienceContains(claims jwtgo.MapClaims, want string) bool {
	vals, ok := ExtractJWTClaimStrings(claims, "aud")
	if !ok {
		return false
	}
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// verifyAccessTokenJWT parses and validates a JWT access token using the AS issuer, JWKS, and audience.
func verifyAccessTokenJWT(raw string, issuer string, audience string, keySet jwk.Set, leeway time.Duration) (jwtgo.MapClaims, error) {
	var claims jwtgo.MapClaims
	token, err := jwtgo.ParseWithClaims(raw, &claims, func(token *jwtgo.Token) (any, error) {
		return authjwt.GetKey(keySet, token)
	},
		jwtgo.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}),
		jwtgo.WithIssuer(issuer),
		jwtgo.WithExpirationRequired(),
		jwtgo.WithIssuedAt(),
		jwtgo.WithLeeway(leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid || claims == nil {
		return nil, ErrInvalidToken
	}
	if !audienceContains(claims, audience) {
		return nil, fmt.Errorf("%w: aud mismatch", ErrInvalidToken)
	}
	return claims, nil
}
