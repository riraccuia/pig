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

func TestEncodeMessageTypeBindingValues(t *testing.T) {
	testCases := []struct {
		name     string
		method   Method
		class    Class
		expected uint16
	}{
		{
			name:     "binding request",
			method:   MethodBinding,
			class:    ClassRequest,
			expected: 0x0001,
		},
		{
			name:     "binding indication",
			method:   MethodBinding,
			class:    ClassIndication,
			expected: 0x0011,
		},
		{
			name:     "binding success response",
			method:   MethodBinding,
			class:    ClassSuccessResponse,
			expected: 0x0101,
		},
		{
			name:     "binding error response",
			method:   MethodBinding,
			class:    ClassErrorResponse,
			expected: 0x0111,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EncodeMessageType(tc.method, tc.class); got != tc.expected {
				t.Fatalf("unexpected encoded type: got 0x%04x want 0x%04x", got, tc.expected)
			}
		})
	}
}

func TestMessageMethodAndClass(t *testing.T) {
	testCases := []struct {
		name       string
		msgType    uint16
		wantMethod Method
		wantClass  Class
	}{
		{
			name:       "binding request",
			msgType:    0x0001,
			wantMethod: MethodBinding,
			wantClass:  ClassRequest,
		},
		{
			name:       "binding success response",
			msgType:    0x0101,
			wantMethod: MethodBinding,
			wantClass:  ClassSuccessResponse,
		},
		{
			name:       "all method bit groups exercised",
			msgType:    0x2b7c,
			wantMethod: 0x0abc,
			wantClass:  ClassErrorResponse,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessageMethod(tc.msgType); got != tc.wantMethod {
				t.Fatalf("unexpected method: got 0x%03x want 0x%03x", got, tc.wantMethod)
			}
			if got := MessageClass(tc.msgType); got != tc.wantClass {
				t.Fatalf("unexpected class: got %d want %d", got, tc.wantClass)
			}
			if got := EncodeMessageType(tc.wantMethod, tc.wantClass); got != tc.msgType {
				t.Fatalf("unexpected round-trip type: got 0x%04x want 0x%04x", got, tc.msgType)
			}
		})
	}
}

func TestMessageTypeClassPredicates(t *testing.T) {
	testCases := []struct {
		name      string
		msgType   uint16
		isRequest bool
		isIndic   bool
		isSuccess bool
		isError   bool
	}{
		{name: "request", msgType: 0x0001, isRequest: true},
		{name: "indication", msgType: 0x0011, isIndic: true},
		{name: "success response", msgType: 0x0101, isSuccess: true},
		{name: "error response", msgType: 0x0111, isError: true},
		{name: "non binding error response", msgType: 0x2b7c, isError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRequestType(tc.msgType); got != tc.isRequest {
				t.Fatalf("unexpected request classification: got %v want %v", got, tc.isRequest)
			}
			if got := IsIndicationType(tc.msgType); got != tc.isIndic {
				t.Fatalf("unexpected indication classification: got %v want %v", got, tc.isIndic)
			}
			if got := IsSuccessResponseType(tc.msgType); got != tc.isSuccess {
				t.Fatalf("unexpected success classification: got %v want %v", got, tc.isSuccess)
			}
			if got := IsErrorResponseType(tc.msgType); got != tc.isError {
				t.Fatalf("unexpected error classification: got %v want %v", got, tc.isError)
			}
		})
	}
}

func TestValidateMethodAndClass(t *testing.T) {
	testCases := []struct {
		name          string
		msgType       uint16
		method        Method
		classes       []Class
		wantErrSubstr string
	}{
		{
			name:    "binding request accepted",
			msgType: MsgTypeBindingRequest,
			method:  MethodBinding,
			classes: []Class{ClassRequest},
		},
		{
			name:          "wrong method rejected",
			msgType:       EncodeMessageType(0x0002, ClassRequest),
			method:        MethodBinding,
			classes:       []Class{ClassRequest},
			wantErrSubstr: "unsupported STUN method",
		},
		{
			name:          "disallowed class rejected",
			msgType:       EncodeMessageType(MethodBinding, ClassIndication),
			method:        MethodBinding,
			classes:       []Class{ClassRequest},
			wantErrSubstr: "unsupported STUN class",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMethodAndClass(tc.msgType, tc.method, tc.classes...)
			if tc.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("ValidateMethodAndClass failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestXorMappedAddressIPv6(t *testing.T) {
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	addr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 3478,
	}

	xorAttr, err := NewXorMappedAddressAttr(addr, txID)
	if err != nil {
		t.Fatalf("NewXorMappedAddressAttr failed: %v", err)
	}
	msg, err := NewMessageWithTransactionID(MsgTypeBindingResponse, []Attribute{xorAttr}, txID)
	if err != nil {
		t.Fatalf("NewMessageWithTransactionID failed: %v", err)
	}

	ip, port, err := msg.MappedAddrPort()
	if err != nil {
		t.Fatalf("ExtractMappedAddress failed: %v", err)
	}

	if !ip.Equal(addr.IP) {
		t.Fatalf("unexpected IP: got %v want %v", ip, addr.IP)
	}

	if port != addr.Port {
		t.Fatalf("unexpected port: got %d want %d", port, addr.Port)
	}
}
