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

package controller

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/auth/jwt"
	"github.com/riraccuia/pig/pkg/auth/oauth"
	"github.com/riraccuia/pig/pkg/auth/oidc"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

func (c *Controller) createClientAuthenticator(cfg *config.AuthConfig) (authenticator common.Authenticator, err error) {
	if cfg == nil || cfg.Type == config.AuthTypeNone {
		return nil, nil
	}

	if !cfg.Type.IsValid() {
		return nil, fmt.Errorf("invalid authentication type: %s", cfg.Type)
	}

	switch cfg.Type {
	case config.AuthTypeOIDC:
		if cfg.OIDC == nil {
			return nil, fmt.Errorf("invalid oidc authentication config")
		}
		authenticator, err = oidc.NewClientAuthenticator(cfg.OIDC.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC authenticator: %w", err)
		}
		c.logger.Infof("OIDC authentication enabled")
	case config.AuthTypeOAuth:
		if cfg.OAuth == nil {
			return nil, fmt.Errorf("invalid oauth authentication config")
		}
		authenticator, err = oauth.NewClientAuthenticator(cfg.OAuth.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth authenticator: %w", err)
		}
		c.logger.Infof("OAuth authentication enabled")
	case config.AuthTypeJWT:
		if cfg.JWT == nil || cfg.JWT.Token == "" {
			return nil, fmt.Errorf("invalid jwt authentication config")
		}
		authenticator, err = jwt.NewClientAuthenticator(cfg.JWT.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
		}
		c.logger.Infof("JWT authentication enabled")
	default:
		return nil, fmt.Errorf("authentication type not implemented: %s", cfg.Type)
	}
	return authenticator, nil
}

func (c *Controller) createServerAuthenticator(cfg *config.AuthConfig) (common.Authenticator, error) {
	if cfg == nil || cfg.Type == config.AuthTypeNone {
		return nil, nil
	}

	if !cfg.Type.IsValid() {
		return nil, fmt.Errorf("invalid authentication type: %s", cfg.Type)
	}

	switch cfg.Type {
	case config.AuthTypeOIDC:
		if cfg.OIDC == nil {
			return nil, fmt.Errorf("invalid oidc authentication config")
		}
		authenticator, err := oidc.NewServerAuthenticator(cfg.OIDC.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC authenticator: %w", err)
		}
		c.logger.Infof("OIDC authentication enabled")
		return authenticator, nil
	case config.AuthTypeOAuth:
		if cfg.OAuth == nil {
			return nil, fmt.Errorf("invalid oauth authentication config")
		}
		authenticator, err := oauth.NewServerAuthenticator(cfg.OAuth.ToConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth authenticator: %w", err)
		}
		c.logger.Infof("OAuth authentication enabled")
		return authenticator, nil
	case config.AuthTypeJWT:
		if cfg.JWT == nil || cfg.JWT.PublicKeySource == "" {
			return nil, fmt.Errorf("invalid jwt authentication config")
		}
		authenticator, err := jwt.NewServerAuthenticator(cfg.JWT.PublicKeySource)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT authenticator: %w", err)
		}
		c.logger.Infof("JWT authentication enabled")
		return authenticator, nil
	default:
		return nil, fmt.Errorf("authentication type not implemented: %s", cfg.Type)
	}
}
