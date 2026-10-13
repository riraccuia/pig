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

package ice

import (
	"fmt"
	"time"

	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

// PathFinder is responsible for gathering ICE candidate paths that are suitable
// towards a target endpoint.
type PathFinder struct {
	opts       *signaling.Options
	protos     []transport.ICEProtocolDefinition
	stunClient *stun.Client
	signaler   *signaling.Signaler
}

func NewPathFinder(opts *signaling.Options, useProtos []transport.ICEProtocolDefinition) (*PathFinder, error) {
	signaler, err := signaling.NewSignaler(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signaler: %w", err)
	}

	dialer := opts.Dialer
	if dialer == nil {
		dialer = network.NewDialer(time.Second * 5)
	}

	stunClient := &stun.Client{
		Dialer:  dialer,
		Logger:  opts.Logger.PrintLevel,
		Servers: opts.STUNServer,
	}
	return &PathFinder{
		opts:       opts,
		protos:     useProtos,
		stunClient: stunClient,
		signaler:   signaler,
	}, nil
}

func (pc *PathFinder) SetConnectOffset(newConnectOffset time.Duration) {
	if newConnectOffset <= 0 {
		return
	}
	pc.opts.ConnectOffset = newConnectOffset
}
