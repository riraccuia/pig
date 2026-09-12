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
	"sync"
	"time"

	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/transport"
)

// PathConnector carries the values shared across the connect and listen path
// flows, so their methods can avoid repeating them in every signature.
type PathConnector struct {
	opts             *signaling.Options
	pigProtos        []transport.ICEProtocolDefinition
	signaler         *signaling.Signaler
	excludedAdapters *sync.Map
}

func NewPathConnector(opts *signaling.Options, pigProtos []transport.ICEProtocolDefinition, excludedAdapters *sync.Map) *PathConnector {
	return &PathConnector{
		opts:             opts,
		pigProtos:        pigProtos,
		excludedAdapters: excludedAdapters,
	}
}

func (pc *PathConnector) SetConnectOffset(newConnectOffset time.Duration) {
	if newConnectOffset <= 0 {
		return
	}
	pc.opts.ConnectOffset = newConnectOffset
}
