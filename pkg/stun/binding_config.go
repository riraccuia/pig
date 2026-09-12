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

// NewBindingAgentConfig builds a BindingAgentConfig for generic STUN short-term
// credentials (RFC 8489 Section 9.1). Passing nil auth disables request/response auth.
func NewBindingAgentConfig(logger LoggerFunc, auth *AuthConfig) *BindingAgentConfig {
	config := &BindingAgentConfig{
		Logger: logger,
		RequestOptions: &BindingOptions{
			RequireFingerprint: true,
		},
		HandleOptions: &BindingOptions{
			RequireFingerprint: true,
		},
	}

	if auth == nil {
		return config
	}

	config.RequestOptions = &BindingOptions{
		Auth: auth,
		// IntegrityPassword: auth.Password,
	}

	config.HandleOptions = &BindingOptions{
		Auth: auth,
		// IntegrityPassword: auth.Password,
	}

	// config.HandleOptions.IntegrityPassword = auth.Password
	/*config.ValidateRequest = func(agent *BindingAgent, request *Message) error {
		if err := ValidateShortTermIntegrity(request, auth); err != nil {
			sendUnauthorizedBindingError(agent, request.Header.TransactionID)
			return err
		}
		return nil
	}*/

	return config
}

// NewControllingICEBindingAgentConfig builds the ICE-specific BindingAgentConfig
// for the controlling side of an ICE connectivity check.
func NewControllingICEBindingAgentConfig(logger LoggerFunc, auth *IceAuth, priority uint32) *BindingAgentConfig {
	return NewICEBindingAgentConfig(logger, auth, &IceConfig{
		Priority:       priority,
		IceControlling: defaultIceTieBreaker,
	})
}

// NewControlledICEBindingAgentConfig builds the ICE-specific BindingAgentConfig
// for the controlled side of an ICE connectivity check.
func NewControlledICEBindingAgentConfig(logger LoggerFunc, auth *IceAuth, priority uint32) *BindingAgentConfig {
	return NewICEBindingAgentConfig(logger, auth, &IceConfig{
		Priority:      priority,
		IceControlled: defaultIceTieBreaker,
	})
}

// NewICEBindingAgentConfig builds a BindingAgentConfig that enables ICE usage.
// Passing nil auth or attributes leaves the corresponding BindingOptions pieces disabled.
func NewICEBindingAgentConfig(logger LoggerFunc, iceAuth *IceAuth, attributes *IceConfig) *BindingAgentConfig {
	config := &BindingAgentConfig{
		Logger: logger,
		RequestOptions: &BindingOptions{
			RequireFingerprint: true,
		},
		HandleOptions: &BindingOptions{
			RequireFingerprint: true,
		},
	}

	if iceAuth == nil {
		iceAuth = &IceAuth{}
	}

	if iceAuth != nil || attributes != nil {
		config.RequestOptions = &BindingOptions{
			RequireFingerprint: true,
		}
	}

	if iceAuth != nil {
		config.RequestOptions.Auth = iceAuth.RequestAuth()
		config.HandleOptions.Auth = iceAuth.ExpectedAuth()
		/*
			config.RequestOptions.IntegrityPassword = iceAuth.OutgoingRequestPassword()
			config.HandleOptions.IntegrityPassword = iceAuth.IncomingRequestPassword()
		*/
		/*config.ValidateRequest = func(agent *BindingAgent, request *Message) error {
			return validateICEBindingRequest(agent, iceAuth, request)
		}*/
	}

	if attributes != nil {
		config.RequestOptions.Ice = attributes
	}

	return config
}
