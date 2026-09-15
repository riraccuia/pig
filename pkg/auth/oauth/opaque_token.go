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
	"net/http"
)

type opaqueTokenVerifier interface {
	verifyOpaque(ctx context.Context, hc *http.Client, token string, rules []ClaimRule) error
}

func newOpaqueTokenVerifier(cfg Config, meta *ProviderMetadata) opaqueTokenVerifier {
	return opaqueVerifierForIssuer(cfg, meta)
}

func opaqueVerifierForIssuer(cfg Config, meta *ProviderMetadata) opaqueTokenVerifier {
	if meta == nil {
		return nil
	}
	cfgIss := NormalizeIssuer(cfg.IssuerURL)
	docIss := NormalizeIssuer(meta.Issuer)
	if !issuerMatchesDiscovery(cfgIss, docIss) {
		return nil
	}
	switch docIss {
	case NormalizeIssuer(IssuerGitHub):
		return githubOpaqueVerifier{}
	case NormalizeIssuer(IssuerGoogle):
		return googleOpaqueVerifier{audience: cfg.EffectiveAudience()}
	default:
		return nil
	}
}
