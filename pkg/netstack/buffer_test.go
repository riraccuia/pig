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

package netstack

import "testing"

func TestRingBufferUsableAfterRelease(t *testing.T) {
	r := newRingBuffer(16)
	r.Write([]byte("queued data"))
	r.release()

	buf := make([]byte, 16)
	if r.Len() != 0 || r.Free() != 16 || r.Peek(0, buf) != 0 || r.Read(buf) != 0 {
		t.Fatalf("released buffer not empty: len %d, free %d", r.Len(), r.Free())
	}
	r.Discard(4)

	if n := r.Write([]byte("again")); n != 5 {
		t.Fatalf("write after release stored %d bytes, want 5", n)
	}
	if n := r.Read(buf); string(buf[:n]) != "again" {
		t.Fatalf("read after release = %q, want again", buf[:n])
	}
}
