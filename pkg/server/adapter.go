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

package server

import (
	"context"
)

func (s *Server) processOutbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.outbound:
			_client, ok := s.clients.Load(pkt.DestinationIP().String())
			if !ok {
				freeBuf := true
				if freeBuf {
					s.bufferPool.Put(pkt.Bytes())
				}
				continue
			}
			client := _client.(*ClientTunnel)

			select {
			case client.outbound.C <- pkt:
			default:
				s.bufferPool.Put(pkt.Bytes())
			}
		}
	}
}
