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

package icmp

import "encoding/binary"

// Helper methods for ICMP sequence wraparound handling.
const maxICMPSeq = 65535 // Maximum value for 16-bit sequence number

// Constants for uint32 sequence number handling.
const (
	maxUint32Seq  = ^uint32(0)
	halfUint32Seq = uint32(1) << 31
)

func getSeqAck(payload []byte) (uint32, uint32) {
	seq := binary.BigEndian.Uint32(payload[0:4])
	ack := binary.BigEndian.Uint32(payload[4:8])
	return seq, ack
}

// isUint32SeqHigher returns true if a is higher than b, accounting for wraparound.
func isUint32SeqHigher(a, b uint32) bool {
	if a == b {
		return false
	}
	return (a - b) < halfUint32Seq
}

// uint32SeqDiff returns the difference between two sequence numbers, accounting for wraparound.
func uint32SeqDiff(a, b uint32) uint32 {
	return a - b // Natural wraparound handles everything!
}
