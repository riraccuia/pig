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

package queue

import (
	"github.com/riraccuia/pig/pkg/common"
)

func zero[T any]() T {
	var z T
	return z
}

func DrainQueue[T any](q any, fn func(val T)) {
	if queue, ok := q.(common.PacketQueue); ok {
		for {
			select {
			case pkt, ok := <-queue:
				if !ok {
					return
				}
				t, ok := pkt.(T)
				if !ok {
					return
				}
				fn(t)
			default:
				return
			}
		}
	}
	if fifo, ok := q.(*FIFO[T]); ok {
		pkts, empty, _ := fifo.TryPopAll()
		if empty {
			return
		}
		for _, pkt := range pkts {
			fn(pkt)
		}
	}
}
