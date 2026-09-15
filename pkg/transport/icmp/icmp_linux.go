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

//go:build linux
// +build linux

package icmp

import (
	"fmt"
	"os"
)

func initSystem() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to set sysctl: %w", err)
	}
	return nil
}
