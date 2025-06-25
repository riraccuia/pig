package stun

import (
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

// IceBindRequest represents a STUN binding request
type IceBindRequest struct {
	Logger common.Logger
	Ice    *IceAttributes
	Auth   *StunAuthConfig
}

// NewIceBindRequest creates a new STUN binding request handler
func NewIceBindRequest(logger common.Logger) *IceBindRequest {
	return &IceBindRequest{
		Logger: logger,
		Ice:    &IceAttributes{},
		Auth:   &StunAuthConfig{},
	}
}

// ReceiveMessage reads a STUN request from the connection
func (b *IceBindRequest) ReceiveMessage(co net.Conn) (message []byte, err error) {
	co.SetReadDeadline(time.Now().Add(stunTimeout))
	defer co.SetReadDeadline(time.Time{})

	message = make([]byte, 1024)
	var n int
	n, err = co.Read(message)
	if err != nil {
		return nil, err
	}
	message = message[:n]
	return
}

// SetAuthConfig sets the authentication configuration for the bind request
func (b *IceBindRequest) SetAuthConfig(username, peerUsername, password, realm, nonce string) {
	b.Auth = &StunAuthConfig{
		SendUsername: peerUsername + ":" + username, // peer_frag:local_frag
		Username:     username,                      // local_frag
		Password:     password,
		Realm:        realm,
		Nonce:        nonce,
	}
}

// SendBindingRequest sends a STUN binding request and returns the mapped address
func (b *IceBindRequest) SendBindingRequest(co net.Conn) (mappedIP net.IP, mappedPort int, err error) {
	var (
		attributes  []byte
		stunRequest *StunMessage
	)

	// Add authentication attributes if present
	if b.Auth != nil {
		b.Logger.Debugf("Sending auth attributes: username=%s, send_username=%s, realm=%s, nonce=%s",
			b.Auth.Username, b.Auth.SendUsername, b.Auth.Realm, b.Auth.Nonce)

		authAttrs := CreateAuthAttributes(b.Auth)
		if len(authAttrs) > 0 {
			attributes = append(attributes, authAttrs...)
		}
	}

	// Add ICE attributes if present
	if b.Ice != nil {
		iceAttrs := CreateIceAttributes(b.Ice)
		if len(iceAttrs) > 0 {
			attributes = append(attributes, iceAttrs...)
		}
	}

	// Create initial message without MESSAGE-INTEGRITY
	stunRequest, err = CreateStunMessage(stunBindingRequest, attributes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create STUN request: %w", err)
	}

	// Add MESSAGE-INTEGRITY attribute if authentication is configured
	if b.Auth != nil && b.Auth.Password != "" {
		stunRequest, err = AddMessageIntegrity(stunRequest, b.Auth.Password)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	err = AddFingerprint(stunRequest)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to add fingerprint: %w", err)
	}

	// Send request
	if _, err = co.Write(stunRequest.Raw); err != nil {
		return nil, 0, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	var (
		stunResponse *StunMessage
		breakLoop    bool
	)

	for {
		message, err := b.ReceiveMessage(co)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read message: %w", err)
		}
		stunResponse, err = ParseStunMessage(message)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse STUN message: %w", err)
		}
		switch stunResponse.Header.Type {
		case stunBindingErrorResponse:
			code, reason := ParseStunError(stunResponse.Attributes)
			return nil, 0, fmt.Errorf("STUN error %d: %s", code, reason)
		case stunBindingRequest:
			if stunResponse.Header.TransactionID != stunRequest.Header.TransactionID {
				// RFC 8445 Section 7.2.2
				// If the server receives a Binding Request, it MUST respond with a Binding Response
				b.HandleBindingRequest(co, message)
				continue
			}
		case stunBindingResponse:
			breakLoop = true
		default:
			return nil, 0, fmt.Errorf("unexpected STUN message type: 0x%x", stunResponse.Header.Type)
		}
		if breakLoop {
			break
		}
	}

	// Validate response
	if err = ValidateStunMessage(stunResponse, stunBindingResponse, stunRequest.Header.TransactionID); err != nil {
		return nil, 0, fmt.Errorf("invalid STUN response: %w", err)
	}

	if !VerifyFingerprint(stunResponse) {
		return nil, 0, fmt.Errorf("invalid STUN response: fingerprint verification failed")
	}

	var (
		ip   net.IP
		port int
	)

	// Parse XOR-MAPPED-ADDRESS
	ip, port, err = ExtractMappedAddress(stunResponse.Attributes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract mapped address: %w", err)
	}

	if ip == nil {
		return nil, 0, fmt.Errorf("no XOR-MAPPED-ADDRESS in response")
	}

	return ip, port, nil
}

// HandleBindingRequest handles an incoming STUN binding request and sends a response
func (b *IceBindRequest) HandleBindingRequest(co net.Conn, requestBytes []byte) error {
	// Parse request
	request, err := ParseStunMessage(requestBytes)
	if err != nil {
		return fmt.Errorf("failed to parse STUN request: %w", err)
	}

	// Validate request type
	if request.Header.Type != stunBindingRequest {
		return fmt.Errorf("unexpected STUN message type: 0x%x", request.Header.Type)
	}

	if !VerifyFingerprint(request) {
		return fmt.Errorf("invalid STUN request: fingerprint verification failed")
	}

	// Parse and validate authentication
	requestAuth, err := b.validateAuthentication(co, request)
	if err != nil {
		return err
	}

	var requestAttrs *IceAttributes
	// Parse ICE attributes if present
	if len(request.Attributes) > 0 {
		requestAttrs, err = ParseIceAttributes(request.Attributes)
		if err != nil {
			return fmt.Errorf("failed to parse ICE attributes: %w", err)
		}
	}
	// TODO: use requestAttrs
	_ = requestAttrs

	// Create response attributes
	responseAttrs, err := CreateResponseAttributes(co.RemoteAddr(), requestAuth)
	if err != nil {
		return fmt.Errorf("failed to create response attributes: %w", err)
	}

	// Create response without MESSAGE-INTEGRITY first
	response, err := CreateStunMessage(stunBindingResponse, responseAttrs)
	if err != nil {
		return fmt.Errorf("failed to create STUN response: %w", err)
	}

	// Copy transaction ID from request
	CopyTransactionID(response, request)

	// Calculate and add message integrity if authentication is required
	if b.Auth != nil && b.Auth.Password != "" {
		response, err = AddMessageIntegrity(response, b.Auth.Password)
		if err != nil {
			return fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	err = AddFingerprint(response)
	if err != nil {
		return fmt.Errorf("failed to add fingerprint: %w", err)
	}

	// Send response
	if _, err := co.Write(response.Raw); err != nil {
		return fmt.Errorf("failed to send STUN response: %w", err)
	}

	return nil
}

// validateAuthentication parses and validates authentication attributes from the request
func (b *IceBindRequest) validateAuthentication(co net.Conn, request *StunMessage) (*StunAuthConfig, error) {
	// Parse authentication attributes if present
	var authAttrs *StunAuthConfig
	if len(request.Attributes) == 0 {
		return nil, nil
	}

	var err error
	authAttrs, err = ParseAuthAttributes(request.Attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentication attributes: %w", err)
	}

	b.Logger.Debugf("Request auth attributes: username=%q, send_username=%q, realm=%q, nonce=%q",
		authAttrs.Username, authAttrs.SendUsername, authAttrs.Realm, authAttrs.Nonce)
	b.Logger.Debugf("Server config: username=%q, send_username=%q, realm=%q, nonce=%q",
		b.Auth.Username, b.Auth.SendUsername, b.Auth.Realm, b.Auth.Nonce)

	// Validate authentication if required
	if b.Auth == nil || b.Auth.Password == "" {
		return nil, nil
	}

	// For ICE, username is formed as "peer_frag:local_frag"
	// See RFC 8445 Section 7.2.2
	if authAttrs.Username == "" {
		b.Logger.Debugf("Invalid ICE username format: %q (expected format: peer_frag:local_frag)", authAttrs.Username)
		SendErrorResponse(co, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("invalid ICE username format")
	}

	// Verify username matches
	if authAttrs.Username != b.Auth.Username {
		b.Logger.Debugf("Username mismatch: expected=%q, got=%q", b.Auth.Username, authAttrs.Username)
		SendErrorResponse(co, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("username mismatch")
	}

	// Verify message integrity
	valid, err := VerifyMessageIntegrity(request, b.Auth.Password)
	if err != nil || !valid {
		b.Logger.Debugf("Message integrity verification failed: %v", err)
		SendErrorResponse(co, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("message integrity verification failed")
	}

	return authAttrs, nil
}
