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

import (
	"fmt"
	"net"
)

// BindingResult captures the common result of a STUN Binding exchange.
type BindingResult struct {
	ServerAddr    string
	TransactionID [12]byte
	IP            net.IP
	Port          int
	//Error         error
}

// BindingOptions enables optional auth and ICE behavior for generalized Binding helpers.
type BindingOptions struct {
	Auth               *AuthConfig
	Ice                *IceConfig
	RequireFingerprint bool
}

func (opts *BindingOptions) BuildAuthAttributes() []Attribute {
	if opts.Auth == nil {
		return nil
	}
	var attrs []Attribute
	if opts.Auth.Username != "" {
		attrs = append(attrs, NewUsernameAttr(opts.Auth.Username))
	}
	if opts.Auth.Realm != "" {
		attrs = append(attrs, NewRealmAttr(opts.Auth.Realm))
	}
	if opts.Auth.Nonce != "" {
		attrs = append(attrs, NewNonceAttr(opts.Auth.Nonce))
	}
	return attrs
}

func (opts *BindingOptions) BuildIceAttributes() []Attribute {
	if opts.Ice == nil {
		return nil
	}
	var attrs []Attribute
	if opts.Ice.UseCandidate {
		attrs = append(attrs, NewICEUseCandidateAttr())
	}
	if opts.Ice.IceControlling > 0 {
		attrs = append(attrs, NewICEControllingAttr(opts.Ice.IceControlling))
	}
	if opts.Ice.IceControlled > 0 {
		attrs = append(attrs, NewICEControlledAttr(opts.Ice.IceControlled))
	}
	if opts.Ice.Priority > 0 {
		attrs = append(attrs, NewICEPriorityAttr(opts.Ice.Priority))
	}
	return attrs
}

// BuildBindingRequest creates a Binding request with optional auth and ICE attributes.
func BuildBindingRequest(opts *BindingOptions) (*Message, error) {
	var attrs []Attribute

	if opts != nil {
		attrs = append(attrs, opts.BuildAuthAttributes()...)
		attrs = append(attrs, opts.BuildIceAttributes()...)
	}

	request, err := NewMessage(MsgTypeBindingRequest, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create STUN request: %w", err)
	}

	if opts != nil && opts.Auth != nil && opts.Auth.Password != "" {
		err = request.AddMessageIntegrity(opts.Auth.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	if opts != nil && opts.RequireFingerprint {
		request = request.WithFingerprint()
	}

	return request, nil
}

// ProcessBindingRequest validates a Binding request and builds its response.
func ProcessBindingRequest(request *Message, remoteAddr net.Addr, validateOpts, opts *BindingOptions) (*Message, error) {
	if request == nil {
		return nil, fmt.Errorf("binding request is required")
	}

	if err := ValidateMethodAndClass(request.Header.Type, MethodBinding, ClassRequest); err != nil {
		return nil, fmt.Errorf("unexpected STUN message type: %w", err)
	}

	if err := request.Validate(validateOpts); err != nil {
		return nil, fmt.Errorf("invalid STUN request: %w", err)
	}

	xorAttr, err := NewXorMappedAddressAttr(remoteAddr, request.Header.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create XOR-MAPPED-ADDRESS: %w", err)
	}

	var attrs []Attribute
	if opts != nil {
		attrs = append(attrs, opts.BuildAuthAttributes()...)
		attrs = append(attrs, opts.BuildIceAttributes()...)
	}
	attrs = append(attrs, xorAttr)

	response, err := NewMessageWithTransactionID(MsgTypeBindingResponse, attrs, request.Header.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create STUN response: %w", err)
	}

	if opts != nil && opts.Auth != nil && opts.Auth.Password != "" {
		// add username to the response
		err = response.AddMessageIntegrity(opts.Auth.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	if opts != nil && opts.RequireFingerprint {
		response = response.WithFingerprint()
	}

	return response, nil
}

// ProcessBindingResponse validates a Binding response and returns its common result.
func ProcessBindingResponse(response *Message, expectedTxID [12]byte, validateOpts *BindingOptions) (*BindingResult, error) {
	result := &BindingResult{
		TransactionID: expectedTxID,
	}
	if response == nil {
		return nil, fmt.Errorf("STUN response is required")
	}

	if err := response.Validate(validateOpts); err != nil {
		return nil, fmt.Errorf("invalid STUN response: %w", err)
	}

	if response.Header.TransactionID != expectedTxID {
		return nil, fmt.Errorf("transaction ID mismatch")
	}

	if err := ValidateMethodAndClass(response.Header.Type, MethodBinding, ClassSuccessResponse, ClassErrorResponse); err != nil {
		return nil, fmt.Errorf("unexpected STUN message type: %w", err)
	}

	switch {
	case IsErrorResponseType(response.Header.Type):
		attrError, err := response.ParseError()
		if err != nil {
			return nil, fmt.Errorf("failed to parse error code attribute: %w", err)
		}
		return nil, fmt.Errorf("STUN error %d: %s", attrError.Code, attrError.Reason)
	case IsSuccessResponseType(response.Header.Type):
	default:
		return nil, fmt.Errorf("unexpected STUN message type: 0x%x", response.Header.Type)
	}

	ip, port, err := response.MappedAddrPort()
	if err != nil {
		return nil, fmt.Errorf("failed to extract mapped address: %w", err)
	}
	if ip == nil {
		return nil, fmt.Errorf("no XOR-MAPPED-ADDRESS in response")
	}

	result.IP = ip
	result.Port = port
	return result, nil
}
