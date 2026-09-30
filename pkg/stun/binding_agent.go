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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type BindingAgentConfig struct {
	// Logger receives agent log events. When nil, a no-op logger is installed.
	Logger LoggerFunc
	// RequestOptions are applied when this agent builds and sends an outgoing
	// Binding request. It may be left nil to send a plain STUN Binding request
	// with the default fingerprint handling.
	RequestOptions *BindingOptions
	// HandleOptions are applied when this agent receives an incoming Binding
	// request, validates it, and builds the corresponding Binding response. It
	// may be left nil to accept plain Binding requests with the default
	// fingerprint requirement.
	HandleOptions *BindingOptions
}

type BindingAgent struct {
	conn    net.Conn
	config  *BindingAgentConfig
	started atomic.Bool
	// ICE nominated flag is set when the connection
	// is nominated for ICE usage by the remote peer.
	nominated    atomic.Bool
	sigNominated atomic.Pointer[chan struct{}]
	requests     *sync.Map
	wg           *sync.WaitGroup
	alive        chan struct{}
	aliveOnce    *sync.Once
}

// requestContext wraps a request context for out of band communication.
// It is used to store the result of a request and the error that occurred
// and to cancel the request if it is timed out.
type requestContext struct {
	done   <-chan struct{}
	cancel context.CancelFunc
	result *BindingResult
	err    error
}

func NewBindingAgent(config *BindingAgentConfig) *BindingAgent {
	agent := &BindingAgent{
		requests:  &sync.Map{},
		wg:        &sync.WaitGroup{},
		alive:     make(chan struct{}, 1),
		aliveOnce: &sync.Once{},
	}
	agent.SetConfig(config)
	return agent
}

func (b *BindingAgent) Clone() *BindingAgent {
	return &BindingAgent{
		config:    b.config,
		requests:  &sync.Map{},
		wg:        &sync.WaitGroup{},
		alive:     make(chan struct{}, 1),
		aliveOnce: &sync.Once{},
	}
}

func (b *BindingAgent) SetConfig(config *BindingAgentConfig) {
	b.config = normalizeBindingAgentConfig(config)
}

// setAlive closes the alive channel to signal that the connection is alive.
// This allows an ICE agent whose first request may not be received by the remote peer
// to be considered alive and continue the ICE negotiation.
func (b *BindingAgent) setAlive() {
	b.aliveOnce.Do(func() {
		close(b.alive)
	})
}

// Receive starts receiving binding requests from the wrapped connection.
func (b *BindingAgent) Receive(conn net.Conn) {
	if conn == nil {
		return
	}
	if !b.started.CompareAndSwap(false, true) {
		return
	}
	b.conn = conn
	b.wg.Go(func() { b.receive() })
}

func (b *BindingAgent) StopReceive() {
	if !b.started.CompareAndSwap(true, false) {
		return
	}
	// get the receive routine to stop now without closeing the connection
	b.conn.SetReadDeadline(time.Now())
	// wait for the receive routine to stop
	b.wg.Wait()
	b.conn.SetReadDeadline(time.Time{})
}

func (b *BindingAgent) logger() LoggerFunc {
	config := b.configOrDefault()
	if config == nil || config.Logger == nil {
		return func(level string, args ...any) {}
	}
	return config.Logger
}

func (b *BindingAgent) configOrDefault() *BindingAgentConfig {
	if b == nil {
		return nil
	}
	if b.config == nil {
		b.config = normalizeBindingAgentConfig(nil)
	}
	return b.config
}

func cloneBindingOptions(options *BindingOptions) *BindingOptions {
	if options == nil {
		return nil
	}

	cloned := *options
	if options.Auth != nil {
		auth := *options.Auth
		cloned.Auth = &auth
	}
	if options.Ice != nil {
		ice := *options.Ice
		cloned.Ice = &ice
	}

	return &cloned
}

func normalizeBindingAgentConfig(config *BindingAgentConfig) *BindingAgentConfig {
	if config == nil {
		return &BindingAgentConfig{
			Logger: func(level string, args ...any) {},
			RequestOptions: &BindingOptions{
				RequireFingerprint: true,
			},
			HandleOptions: &BindingOptions{
				RequireFingerprint: true,
			},
		}
	}

	normalized := *config
	if normalized.Logger == nil {
		normalized.Logger = func(level string, args ...any) {}
	}
	normalized.RequestOptions = cloneBindingOptions(config.RequestOptions)
	normalized.HandleOptions = cloneBindingOptions(config.HandleOptions)
	if normalized.HandleOptions == nil {
		normalized.HandleOptions = &BindingOptions{
			RequireFingerprint: true,
		}
	}

	return &normalized
}

func (b *BindingAgent) receive() {
	for {
		message, err := ReceiveMessageFromConn(b.conn)
		if err != nil && err != ErrParseMessage {
			b.logger()("trace", fmt.Sprintf("BIND: failed to receive message: %v", err))
			return
		}
		if err == ErrParseMessage {
			b.logger()("error", err.Error())
			continue
		}

		if err := ValidateMethodAndClass(message.Header.Type, MethodBinding, ClassRequest); err == nil {
			err = b.HandleRequest(message)
			if err != nil {
				b.logger()("trace", fmt.Sprintf("BIND: failed to handle binding request: %v", err))
			}
			b.setAlive()
			continue
		}
		if err := ValidateMethodAndClass(message.Header.Type, MethodBinding, ClassSuccessResponse, ClassErrorResponse); err == nil {
			v, ok := b.requests.Load(message.Header.TransactionID)
			if !ok {
				//b.Logger.Errorf("no request found for transaction ID: %x", message.Header.TransactionID)
				b.setAlive()
				continue
			}
			rc := v.(*requestContext)
			select {
			case <-rc.done:
				// request context is done (timed out)
				b.setAlive()
				continue
			default:
			}
			rc.result, rc.err = b.HandleResponse(message, message.Header.TransactionID)
			rc.cancel()
		}

		b.setAlive()
	}
}

// ReceiveMessageFromConn receives a STUN message from a connection.
func ReceiveMessageFromConn(conn net.Conn) (message *Message, err error) {
	var (
		rawMessage = make([]byte, 1024)
		n          int
	)
	if _, ok := conn.(*net.UDPConn); ok {
		n, err = conn.Read(rawMessage)
		if err != nil {
			return nil, err
		}
		message, err = DecodeMessage(rawMessage[:n])
		if err != nil {
			return nil, ErrParseMessage
		}
		return message, nil
	}
	n, err = io.ReadFull(conn, rawMessage[:20])
	if err != nil {
		return nil, err
	}
	if n < 20 {
		return nil, fmt.Errorf("STUN message too short: %d bytes", n)
	}
	//rawMessage = rawMessage[:n]
	msgLen := binary.BigEndian.Uint16(rawMessage[2:4])
	if msgLen > uint16(len(rawMessage)-20) {
		rawMessage = append(rawMessage[:20], make([]byte, int(msgLen))...)
	}
	n, err = io.ReadFull(conn, rawMessage[20:20+msgLen])
	if err != nil {
		return nil, err
	}
	message, err = DecodeMessage(rawMessage[:20+msgLen])
	if err != nil {
		//b.Logger.Errorf("Failed to parse STUN message from %s: %v", conn.RemoteAddr(), err)
		return nil, ErrParseMessage
	}
	return message, nil
}

func (b *BindingAgent) Bind(ctx context.Context) (result *BindingResult, err error) {
	request, err := BuildBindingRequest(b.configOrDefault().RequestOptions)
	if err != nil {
		return nil, err
	}

	bctx, cancel := context.WithCancel(ctx)

	rc := &requestContext{done: bctx.Done(), cancel: cancel}
	b.requests.Store(request.Header.TransactionID, rc)

	_, err = request.WriteTo(b.conn)
	if err != nil {
		cancel()
		b.requests.Delete(request.Header.TransactionID)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	select {
	case <-b.alive:
		b.logger()("trace", "BIND: connection is alive, sending request")
		cancel()
		b.requests.Delete(request.Header.TransactionID)
		if rc.result != nil || rc.err != nil {
			return rc.result, rc.err
		}
		return b.SendRequest(ctx, true)
	case <-bctx.Done():
	}

	b.requests.Delete(request.Header.TransactionID)
	if rc.result != nil || rc.err != nil {
		return rc.result, rc.err
	}
	return nil, bctx.Err()
}

// SendRequest sends a STUN binding request and returns the mapped address.
func (b *BindingAgent) SendRequest(ctx context.Context, waitForResponse bool) (result *BindingResult, err error) {
	if !b.started.Load() {
		return nil, fmt.Errorf("binding agent is not started")
	}

	request, err := BuildBindingRequest(b.configOrDefault().RequestOptions)
	if err != nil {
		return nil, err
	}

	bctx, cancel := context.WithCancel(ctx)
	rc := &requestContext{done: bctx.Done(), cancel: cancel}
	b.requests.Store(request.Header.TransactionID, rc)

	// Send request
	_, err = request.WriteTo(b.conn)
	if err != nil {
		cancel()
		b.requests.Delete(request.Header.TransactionID)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	b.logger()("trace", fmt.Sprintf("BIND: sent request with transaction ID: %x", request.Header.TransactionID))

	if !waitForResponse {
		cancel()
		b.requests.Delete(request.Header.TransactionID)
		return nil, nil
	}

	<-bctx.Done()
	b.requests.Delete(request.Header.TransactionID)

	if rc.result != nil || rc.err != nil {
		return rc.result, rc.err
	}
	return nil, bctx.Err()
}

// HandleResponse parses a STUN response and returns the binding result.
func (b *BindingAgent) HandleResponse(response *Message, transactionID [12]byte) (*BindingResult, error) {
	return ProcessBindingResponse(response, transactionID, b.configOrDefault().HandleOptions)
}

// HandleRequest handles an incoming STUN binding request and sends a response
func (b *BindingAgent) HandleRequest(request *Message) error {
	if b.conn == nil {
		return fmt.Errorf("binding connection is not set")
	}

	response, err := ProcessBindingRequest(request, b.conn.RemoteAddr(), b.configOrDefault().HandleOptions, b.configOrDefault().RequestOptions)
	if err != nil {
		return err
	}

	// Send response
	_, err = response.WriteTo(b.conn)
	if err != nil {
		return fmt.Errorf("failed to send STUN response: %w", err)
	}

	if b.config.HandleOptions.Ice == nil {
		return nil
	}

	if b.config.HandleOptions.Ice.IceControlled == 0 {
		return nil
	}

	if _, ok := request.FindAttribute(AttrICEUseCandidate); ok {
		b.nominated.CompareAndSwap(false, true)
		if ch := b.sigNominated.Load(); ch != nil {
			close(*ch)
		}
		b.logger()("debug", fmt.Sprintf("BIND: ICE use candidate attribute found in request, nominated: %t", b.nominated.Load()))
		return nil
	}

	return nil
}

// ICENominated returns true if the binding agent is nominated for ICE usage by the remote peer.
func (b *BindingAgent) ICENominated() bool {
	return b.nominated.Load()
}

// ICEWaitNominated waits for the binding agent to be nominated for ICE usage by the remote peer.
// It will block until either the context is done or the binding agent is nominated.
// Only controlled agents can call this method.
func (b *BindingAgent) ICEWaitNominated(ctx context.Context) (nominated bool, err error) {
	// if this is not the controlling agent, return immediately
	if b.config.HandleOptions.Ice == nil || b.config.HandleOptions.Ice.IceControlled == 0 {
		return false, errors.New("not the controlled agent")
	}
	ch := make(chan struct{}, 1)
	if !b.sigNominated.CompareAndSwap(nil, &ch) {
		return false, errors.New("nominated channel already set")
	}
	defer b.sigNominated.Store(nil)
	if b.nominated.Load() {
		return true, nil
	}
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-ch:
		nominated = true
	}
	return
}

// ICENominateCandidate sets the ICE nominated flag to true, then calls
// [BindingAgent.SendRequest] to tell the other side that we are going to use
// this candidate. It returns the binding result.
// Only controlling agents can call this method.
func (b *BindingAgent) ICENominateCandidate(ctx context.Context) (*BindingResult, error) {
	// if this is not the controlling agent, return immediately
	if b.config.RequestOptions.Ice == nil || b.config.RequestOptions.Ice.IceControlling == 0 {
		return nil, errors.New("not the controlling agent")
	}
	b.config.RequestOptions.Ice.UseCandidate = true
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	return b.SendRequest(ctx, true)
}

// ICEPriority returns the ICE priority of the binding agent.
func (b *BindingAgent) ICEPriority() uint32 {
	config := b.configOrDefault()
	if config == nil || config.RequestOptions == nil || config.RequestOptions.Ice == nil {
		return 0
	}
	return config.RequestOptions.Ice.Priority
}
