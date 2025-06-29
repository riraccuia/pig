package stun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

var ErrParseStunMessage = errors.New("failed to parse STUN message")

type IceBindingAgent struct {
	Conn         net.Conn
	Logger       common.Logger
	Ice          *IceAttributes
	Auth         *StunAuthConfig
	UseCandidate *bool
	started      atomic.Bool
	requests     *sync.Map
}

func NewIceBindingAgent(logger common.Logger, conn net.Conn) *IceBindingAgent {
	return &IceBindingAgent{
		Conn:     conn,
		Logger:   logger,
		requests: &sync.Map{},
	}
}

type IceBindingResult struct {
	TransactionID [12]byte
	IP            net.IP
	Port          int
	Error         error
}

func (b *IceBindingAgent) IsControlling() bool {
	return b.Ice != nil && b.Ice.IceControlling != 0
}

func (b *IceBindingAgent) IsNominated() bool {
	return b.UseCandidate != nil && *b.UseCandidate
}

func (b *IceBindingAgent) Receive() {
	go b.receive()
}

func (b *IceBindingAgent) receive() {
	if !b.started.CompareAndSwap(false, true) {
		return
	}
	defer b.started.Store(false)
	for {
		message, err := ReceiveMessage(b.Conn)
		if err != nil && err != ErrParseStunMessage {
			//b.Logger.Errorf("Failed to receive message: %v", err)
			return
		}
		if err == ErrParseStunMessage {
			continue
		}
		// if message is a binding request, handle it
		if message.Header.Type == stunBindingRequest {
			b.HandleBindingRequest(message)
			continue
		}
		if message.Header.Type == stunBindingResponse {
			_, ok := b.requests.Load(message.Header.TransactionID)
			if !ok {
				//b.Logger.Errorf("no request found for transaction ID: %x", message.Header.TransactionID)
				continue
			}
			b.HandleBindingResponse(message.Header.TransactionID, message)
		}
	}
}

func (b *IceBindingAgent) StopReceive() {
	if !b.started.Load() {
		return
	}
	// get the receive routine to stop now without closeing the connection
	b.Conn.SetReadDeadline(time.Now())
	defer b.Conn.SetReadDeadline(time.Time{})
	// wait for the receive routine to stop
	for b.started.Load() {
		time.Sleep(time.Millisecond * 100)
	}
}

func ReceiveMessage(conn net.Conn) (message *StunMessage, err error) {
	var (
		rawMessage = make([]byte, 1024)
		n          int
	)
	if _, ok := conn.(*net.UDPConn); ok {
		n, err = conn.Read(rawMessage)
		if err != nil {
			return nil, err
		}
		message, err = ParseStunMessage(rawMessage[:n])
		if err != nil {
			return nil, ErrParseStunMessage
		}
		return message, nil
	}
	n, err = conn.Read(rawMessage[:20])
	if err != nil {
		return nil, err
	}
	if n < 20 {
		return nil, fmt.Errorf("STUN message too short: %d bytes", n)
	}
	//rawMessage = rawMessage[:n]
	msgLen := binary.BigEndian.Uint16(rawMessage[2:4])
	if msgLen > 1024 {
		return nil, fmt.Errorf("STUN message too long: %d bytes", msgLen)
	}
	n, err = conn.Read(rawMessage[20 : 20+msgLen])
	if err != nil {
		return nil, err
	}
	message, err = ParseStunMessage(rawMessage[:20+n])
	if err != nil {
		//b.Logger.Errorf("Failed to parse STUN message from %s: %v", conn.RemoteAddr(), err)
		return nil, ErrParseStunMessage
	}
	return message, nil
}

// SetAuthConfig sets the authentication configuration for the bind request
func (b *IceBindingAgent) SetAuthConfig(username, peerUsername, password, peerPassword string) {
	b.Auth = &StunAuthConfig{
		Username:     username, // local_frag
		Password:     password,
		PeerUsername: peerUsername, // peer_frag
		PeerPassword: peerPassword,
	}
}

// SendBindingRequest sends a STUN binding request and returns the mapped address
func (b *IceBindingAgent) SendBindingRequest(waitForResponse bool) (result *IceBindingResult, err error) {
	var (
		attributes  []byte
		stunRequest *StunMessage
	)

	// Add authentication attributes if present
	if b.Auth != nil {
		//b.Logger.Debugf("Sending auth attributes: username=%s, peer_username=%s, realm=%s, nonce=%s",
		//	b.Auth.Username, b.Auth.PeerUsername, b.Auth.Realm, b.Auth.Nonce)

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
		return nil, fmt.Errorf("failed to create STUN request: %w", err)
	}

	// Add MESSAGE-INTEGRITY attribute if authentication is configured
	if b.Auth != nil && b.Auth.PeerPassword != "" {
		stunRequest, err = AddMessageIntegrity(stunRequest, b.Auth.PeerPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	err = AddFingerprint(stunRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to add fingerprint: %w", err)
	}

	// Send request
	if _, err = b.Conn.Write(stunRequest.Raw); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if !waitForResponse || b.started.Load() {
		b.requests.Store(stunRequest.Header.TransactionID, nil)
		return
	}

	// Read response
	var (
		stunResponse *StunMessage
		stop         bool
	)

	for !stop {
		b.Conn.SetReadDeadline(time.Now().Add(stunTimeout))
		stunResponse, err = ReceiveMessage(b.Conn)
		b.Conn.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, fmt.Errorf("failed to read message: %w", err)
		}
		switch stunResponse.Header.Type {
		case stunBindingErrorResponse:
			code, reason := ParseStunError(stunResponse.Attributes)
			err = fmt.Errorf("STUN error %d: %s", code, reason)
			result = &IceBindingResult{
				TransactionID: stunRequest.Header.TransactionID,
				Error:         err,
			}
			return
		case stunBindingRequest:
			if stunResponse.Header.TransactionID != stunRequest.Header.TransactionID {
				// RFC 8445 Section 7.2.2
				// If the server receives a Binding Request, it MUST respond with a Binding Response
				b.HandleBindingRequest(stunResponse)
				continue
			}
		case stunBindingResponse:
			stop = true
		default:
			return nil, fmt.Errorf("unexpected STUN message type: 0x%x", stunResponse.Header.Type)
		}
	}

	return b.HandleBindingResponse(stunRequest.Header.TransactionID, stunResponse)
}

func (b *IceBindingAgent) HandleBindingResponse(transactionID [12]byte, response *StunMessage) (*IceBindingResult, error) {
	var (
		err    error
		ip     net.IP
		port   int
		result = &IceBindingResult{
			TransactionID: transactionID,
		}
	)
	// Validate response
	if err = ValidateStunMessage(response, stunBindingResponse, transactionID); err != nil {
		return nil, fmt.Errorf("invalid STUN response: %w", err)
	}

	if !VerifyFingerprint(response) {
		return nil, fmt.Errorf("invalid STUN response: fingerprint verification failed")
	}

	// Parse XOR-MAPPED-ADDRESS
	ip, port, err = ExtractMappedAddress(response.Attributes)
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

// HandleBindingRequest handles an incoming STUN binding request and sends a response
func (b *IceBindingAgent) HandleBindingRequest(request *StunMessage) error {
	// Validate request type
	if request.Header.Type != stunBindingRequest {
		return fmt.Errorf("unexpected STUN message type: 0x%x", request.Header.Type)
	}

	if !VerifyFingerprint(request) {
		return fmt.Errorf("invalid STUN request: fingerprint verification failed")
	}

	// Parse and validate authentication
	requestAuth, err := b.validateAuthentication(request)
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

	var useCandidate bool
	if requestAttrs != nil && requestAttrs.UseCandidate {
		useCandidate = true
		defer func() {
			b.UseCandidate = &useCandidate
		}()
	}

	// Create response attributes
	responseAttrs, err := CreateResponseAttributes(b.Conn.RemoteAddr(), requestAuth)
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
	if b.Auth != nil && b.Auth.PeerPassword != "" {
		response, err = AddMessageIntegrity(response, b.Auth.PeerPassword)
		if err != nil {
			return fmt.Errorf("failed to add message integrity: %w", err)
		}
	}

	err = AddFingerprint(response)
	if err != nil {
		return fmt.Errorf("failed to add fingerprint: %w", err)
	}

	// Send response
	if _, err := b.Conn.Write(response.Raw); err != nil {
		return fmt.Errorf("failed to send STUN response: %w", err)
	}

	return nil
}

// validateAuthentication parses and validates authentication attributes from the request
func (b *IceBindingAgent) validateAuthentication(request *StunMessage) (*StunAuthConfig, error) {
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

	//b.Logger.Debugf("Request auth attributes: username=%q, peer_username=%q, realm=%q, nonce=%q",
	//	authAttrs.Username, authAttrs.PeerUsername, authAttrs.Realm, authAttrs.Nonce)
	//b.Logger.Debugf("Server config: username=%q, peer_username=%q, realm=%q, nonce=%q",
	//	b.Auth.Username, b.Auth.PeerUsername, b.Auth.Realm, b.Auth.Nonce)

	// Validate authentication if required
	if b.Auth == nil || b.Auth.Password == "" {
		return nil, nil
	}

	// For ICE, username is formed as "peer_frag:local_frag"
	// See RFC 8445 Section 7.2.2
	if authAttrs.Username == "" {
		b.Logger.Debugf("Invalid ICE username format: %q (expected format: peer_frag:local_frag)", authAttrs.Username)
		SendErrorResponse(b.Conn, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("invalid ICE username format")
	}

	// Verify username matches
	if authAttrs.Username != b.Auth.Username {
		b.Logger.Debugf("Username mismatch: expected=%q, got=%q", b.Auth.Username, authAttrs.Username)
		SendErrorResponse(b.Conn, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("username mismatch")
	}

	// Verify message integrity
	valid, err := VerifyMessageIntegrity(request, b.Auth.Password)
	if err != nil || !valid {
		b.Logger.Debugf("Message integrity verification failed: %v", err)
		SendErrorResponse(b.Conn, request.Header.TransactionID, 401, "Unauthorized", b.Auth)
		return nil, fmt.Errorf("message integrity verification failed")
	}

	return authAttrs, nil
}
