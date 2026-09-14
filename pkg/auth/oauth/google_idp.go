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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// IssuerGoogle is the Google OAuth / OpenID issuer.
// Discovery uses RFC 8414 against accounts.google.com.
const IssuerGoogle = "https://accounts.google.com"

const googleTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"

type googleOpaqueVerifier struct {
	// audience, when non-empty, must match tokeninfo aud or azp.
	audience string
}

func (v googleOpaqueVerifier) verifyOpaque(ctx context.Context, hc *http.Client, token string, rules []ClaimRule) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	info, err := fetchGoogleTokenInfo(ctx, hc, token)
	if err != nil {
		return err
	}
	if err := validateGoogleTokenInfo(info, v.audience); err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	return validateClaimRulesStringValues(rules, func(claim string) ([]string, bool, error) {
		return googleTokenInfoClaimValues(info, claim)
	})
}

type googleTokenInfo struct {
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Scope         string `json:"scope"`
	Exp           string `json:"exp"`
	ExpiresIn     string `json:"expires_in"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	AccessType    string `json:"access_type"`
	Error         string `json:"error"`
	ErrorDesc     string `json:"error_description"`
}

func fetchGoogleTokenInfo(ctx context.Context, hc *http.Client, accessToken string) (*googleTokenInfo, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	u, err := url.Parse(googleTokenInfoURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("access_token", accessToken)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pig-oauth-server")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: google tokeninfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var info googleTokenInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("%w: google tokeninfo JSON: %v", ErrInvalidToken, err)
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(info.Error) != "" {
		msg := strings.TrimSpace(info.ErrorDesc)
		if msg == "" {
			msg = strings.TrimSpace(info.Error)
		}
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		return nil, fmt.Errorf("%w: google tokeninfo: %s: %s", ErrInvalidToken, resp.Status, msg)
	}
	return &info, nil
}

func validateGoogleTokenInfo(info *googleTokenInfo, audience string) error {
	if info == nil {
		return ErrInvalidToken
	}
	if exp := strings.TrimSpace(info.Exp); exp != "" {
		sec, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: google tokeninfo invalid exp", ErrInvalidToken)
		}
		if time.Now().Unix() >= sec {
			return fmt.Errorf("%w: google access token expired", ErrInvalidToken)
		}
	}
	aud := strings.TrimSpace(audience)
	if aud != "" {
		if strings.TrimSpace(info.Aud) != aud && strings.TrimSpace(info.Azp) != aud {
			return fmt.Errorf("%w: google tokeninfo aud/azp mismatch", ErrInvalidToken)
		}
	}
	return nil
}

func googleTokenInfoClaimValues(info *googleTokenInfo, claim string) ([]string, bool, error) {
	switch strings.TrimSpace(claim) {
	case "email":
		em := strings.TrimSpace(info.Email)
		if em == "" {
			return nil, false, nil
		}
		if !googleEmailVerified(info.EmailVerified) {
			return nil, false, nil
		}
		return []string{em}, true, nil
	case "email_verified":
		v := strings.TrimSpace(info.EmailVerified)
		if v == "" {
			return nil, false, nil
		}
		return []string{v}, true, nil
	case "sub":
		s := strings.TrimSpace(info.Sub)
		if s == "" {
			return nil, false, nil
		}
		return []string{s}, true, nil
	case "aud":
		s := strings.TrimSpace(info.Aud)
		if s == "" {
			return nil, false, nil
		}
		return []string{s}, true, nil
	case "azp":
		s := strings.TrimSpace(info.Azp)
		if s == "" {
			return nil, false, nil
		}
		return []string{s}, true, nil
	case "scope":
		scopes := strings.Fields(info.Scope)
		if len(scopes) == 0 {
			return nil, false, nil
		}
		return scopes, true, nil
	default:
		return nil, false, fmt.Errorf("%w: google opaque: unsupported claim %q for claim_matchers", ErrInvalidToken, claim)
	}
}

func googleEmailVerified(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1":
		return true
	default:
		return false
	}
}
