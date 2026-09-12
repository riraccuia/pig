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
	"net"
	"strings"
	"testing"
)

func TestGenericAuthAttributesRoundTrip(t *testing.T) {
	auth := &AuthConfig{
		Username: "generic-user",
		Realm:    "example.org",
		Nonce:    "nonce-value",
	}

	var attrs []Attribute
	if auth.Username != "" {
		attrs = append(attrs, NewUsernameAttr(auth.Username))
	}
	if auth.Realm != "" {
		attrs = append(attrs, NewRealmAttr(auth.Realm))
	}
	if auth.Nonce != "" {
		attrs = append(attrs, NewNonceAttr(auth.Nonce))
	}

	msg, err := NewMessage(MsgTypeBindingRequest, attrs)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}

	parsed, err := msg.GetAuthParams()
	if err != nil {
		t.Fatalf("GetAuthParams failed: %v", err)
	}

	if parsed.Username != auth.Username {
		t.Fatalf("unexpected username: got %q want %q", parsed.Username, auth.Username)
	}
	if parsed.Realm != auth.Realm {
		t.Fatalf("unexpected realm: got %q want %q", parsed.Realm, auth.Realm)
	}
	if parsed.Nonce != auth.Nonce {
		t.Fatalf("unexpected nonce: got %q want %q", parsed.Nonce, auth.Nonce)
	}
}

func TestIceAuthConfigHelpers(t *testing.T) {
	auth := &IceAuth{
		LocalUfrag:     "local",
		LocalPassword:  "local-pass",
		RemoteUfrag:    "remote",
		RemotePassword: "remote-pass",
	}

	requestAuth := auth.RequestAuth()
	if requestAuth == nil {
		t.Fatal("expected request auth")
	}
	if requestAuth.Username != "remote:local" {
		t.Fatalf("unexpected outgoing username: got %q want %q", requestAuth.Username, "remote:local")
	}
	if auth.ExpectedIncomingUsername() != "local:remote" {
		t.Fatalf("unexpected incoming username: got %q want %q", auth.ExpectedIncomingUsername(), "local:remote")
	}
	if auth.OutgoingRequestPassword() != "remote-pass" {
		t.Fatalf("unexpected outgoing password: got %q want %q", auth.OutgoingRequestPassword(), "remote-pass")
	}
	if auth.IncomingRequestPassword() != "local-pass" {
		t.Fatalf("unexpected incoming password: got %q want %q", auth.IncomingRequestPassword(), "local-pass")
	}
}

func TestBindingHelpersPlainRoundTrip(t *testing.T) {
	request, err := BuildBindingRequest(nil)
	if err != nil {
		t.Fatalf("BuildBindingRequest failed: %v", err)
	}

	if err := request.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint failed: %v", err)
	}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 3478,
	}
	response, err := ProcessBindingRequest(request, remoteAddr, &BindingOptions{
		RequireFingerprint: true,
	}, nil)
	if err != nil {
		t.Fatalf("ProcessBindingRequest failed: %v", err)
	}

	if err := response.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint failed: %v", err)
	}

	result, err := ProcessBindingResponse(response, request.Header.TransactionID, &BindingOptions{
		RequireFingerprint: true,
	})
	if err != nil {
		t.Fatalf("ParseBindingResponse failed: %v", err)
	}
	if !result.IP.Equal(remoteAddr.IP) {
		t.Fatalf("unexpected IP: got %v want %v", result.IP, remoteAddr.IP)
	}
	if result.Port != remoteAddr.Port {
		t.Fatalf("unexpected port: got %d want %d", result.Port, remoteAddr.Port)
	}
}

func TestBindingHelpersWithICEAndAuth(t *testing.T) {
	auth := &AuthConfig{
		Username: "peer_frag:local_frag",
		Password: "peer_pass",
	}
	ice := &IceConfig{
		Priority:       1234,
		UseCandidate:   true,
		IceControlling: 99,
	}

	request, err := BuildBindingRequest(&BindingOptions{
		Auth: auth,
		Ice:  ice,
	})
	if err != nil {
		t.Fatalf("BuildBindingRequest failed: %v", err)
	}

	if err := request.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint failed: %v", err)
	}

	err = request.Validate(&BindingOptions{
		RequireFingerprint: true,
		Auth:               auth,
	})
	if err != nil {
		t.Fatalf("ValidateBindingRequest failed: %v", err)
	}
	rAuth, err := request.GetAuthParams()
	if err != nil {
		t.Fatalf("GetAuthParams failed: %v", err)
	}
	if rAuth == nil {
		t.Fatal("expected parsed auth attributes")
	}
	if rAuth.Username != auth.Username {
		t.Fatalf("unexpected parsed username: got %q want %q", rAuth.Username, auth.Username)
	}
	rIce, err := ParseIceAttributesFromMessage(request)
	if err != nil {
		t.Fatalf("GetIceAttributes failed: %v", err)
	}
	if rIce == nil {
		t.Fatal("expected parsed ICE attributes")
	}
	if rIce.Priority != ice.Priority {
		t.Fatalf("unexpected ICE priority: got %d want %d", rIce.Priority, ice.Priority)
	}
	if !rIce.UseCandidate {
		t.Fatal("expected USE-CANDIDATE to be set")
	}
	if rIce.IceControlling != ice.IceControlling {
		t.Fatalf("unexpected ICE controlling value: got %d want %d", rIce.IceControlling, ice.IceControlling)
	}
}

func TestProcessBindingRequest(t *testing.T) {
	request, err := BuildBindingRequest(nil)
	if err != nil {
		t.Fatalf("BuildBindingRequest failed: %v", err)
	}

	if err := request.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint failed: %v", err)
	}

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 9999,
	}

	response, err := ProcessBindingRequest(request, remoteAddr, &BindingOptions{RequireFingerprint: true}, &BindingOptions{RequireFingerprint: true})
	if err != nil {
		t.Fatalf("ProcessBindingRequest failed: %v", err)
	}

	/*if requestState == nil || requestState.Message == nil {
		t.Fatal("expected parsed binding request state")
	}*/

	if err := response.AddFingerprint(); err != nil {
		t.Fatalf("AddFingerprint failed: %v", err)
	}

	result, err := ProcessBindingResponse(response, request.Header.TransactionID, &BindingOptions{
		RequireFingerprint: true,
	})
	if err != nil {
		t.Fatalf("ParseBindingResponse failed: %v", err)
	}
	if !result.IP.Equal(remoteAddr.IP) {
		t.Fatalf("unexpected IP: got %v want %v", result.IP, remoteAddr.IP)
	}
	if result.Port != remoteAddr.Port {
		t.Fatalf("unexpected port: got %d want %d", result.Port, remoteAddr.Port)
	}
}

func TestValidateBindingRequestRejectsInvalidMagicCookie(t *testing.T) {
	request, err := BuildBindingRequest(nil)
	if err != nil {
		t.Fatalf("BuildBindingRequest failed: %v", err)
	}

	raw := append([]byte(nil), request.Raw.Bytes()...)
	raw[4] = 0
	raw[5] = 0
	raw[6] = 0
	raw[7] = 0

	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("ParseStunMessage failed: %v", err)
	}

	err = message.Validate(&BindingOptions{
		RequireFingerprint: true,
	})
	if err == nil {
		t.Fatal("expected invalid magic cookie error")
	}
	if !strings.Contains(err.Error(), "invalid magic cookie") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBindingRequestRejectsInvalidTypeBits(t *testing.T) {
	request, err := BuildBindingRequest(nil)
	if err != nil {
		t.Fatalf("BuildBindingRequest failed: %v", err)
	}

	raw := append([]byte(nil), request.Raw.Bytes()...)
	raw[0] = 0x40

	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("ParseStunMessage failed: %v", err)
	}

	err = message.Validate(nil)
	if err == nil {
		t.Fatal("expected invalid message type bits error")
	}
	if !strings.Contains(err.Error(), "top two bits must be zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseBindingResponseRejectsMismatchedErrorTransaction(t *testing.T) {
	expectedTxID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	otherTxID := [12]byte{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	response, err := CreateErrorMessage(otherTxID, 401, "Unauthorized")
	if err != nil {
		t.Fatalf("CreateErrorResponse failed: %v", err)
	}

	_, err = ProcessBindingResponse(response, expectedTxID, nil)
	if err == nil {
		t.Fatal("expected transaction mismatch error")
	}
	if !strings.Contains(err.Error(), "transaction ID mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}
