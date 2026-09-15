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

//go:build !windows && !darwin && unix

package network

import "golang.org/x/sys/unix"

// setSockoptIPV6DontFrag sets the IP_PMTUDISC_PROBE socket option.
// https://www.ietf.org/archive/id/draft-seemann-tsvwg-udp-fragmentation-02.txt
func setSockoptIPV6DontFrag(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IP_PMTUDISC_PROBE, 1)
}

func setSockoptReuseAddr(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
}

func setSockoptReusePort(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
