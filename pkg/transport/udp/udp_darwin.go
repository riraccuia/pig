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

//go:build darwin
// +build darwin

package udp

import (
	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/sys/unix"
)

func initUDP(logger common.Logger) {
	// Get UDP max datagram size using Sysctl
	value, err := unix.Sysctl("net.inet.udp.maxdgram")
	if err != nil {
		logger.Errorf("Failed to get UDP maxdgram: %v", err)
		return
	}

	bytes := []byte(value)
	length := len(bytes)
	if length == 0 {
		logger.Errorf("Empty value returned from sysctl for UDP maxdgram")
		return
	}

	// Combine bytes in little-endian order
	maxDgram := 0
	for i := 0; i < length && i < 4; i++ { // limit to 4 bytes (32 bits)
		maxDgram |= int(bytes[i]) << (i * 8)
	}

	defaultBufferSize = maxDgram
}
