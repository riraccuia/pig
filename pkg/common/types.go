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

package common

import (
	"net"

	"github.com/riraccuia/pig/pkg/network"
)

type PacketQueue chan network.IPPacket

type TunnelAdapter interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	IP() net.IP
	IPNet() *net.IPNet
	IP6() net.IP
	IPNet6() *net.IPNet
	Name() string
	Index() int
}

type Logger interface {
	SetLevel(level string)
	PrintLevel(level string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Debug(args ...any)
	Debugf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Trace(args ...any)
	Tracef(format string, args ...any)
}
