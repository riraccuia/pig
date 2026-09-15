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

package adapter

import (
	"github.com/riraccuia/pig/pkg/common"
)

type AdapterConfig struct {
	Address []string
	MTU     int
	// MultiQueue enables tun multi-queue support
	// It is only supported on Linux
	MultiQueue bool
}

func NewAdapter(cfg AdapterConfig) (common.TunnelAdapter, error) {
	return newAdapter(cfg)
}
