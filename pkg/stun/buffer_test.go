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

package stun

import (
	"bytes"
	"testing"
)

func TestBuffer_edge_zeroBuffer(t *testing.T) {
	var b Buffer
	if len(b.Bytes()) != 0 {
		t.Fatalf("Bytes: len %d", len(b.Bytes()))
	}
}

func TestBuffer_edge_appendZero(t *testing.T) {
	var b Buffer
	copy(b.Append(1), []byte{0xAA})
	b.Append(0)
	if !bytes.Equal(b.Bytes(), []byte{0xAA}) {
		t.Fatalf("got %v", b.Bytes())
	}
}

func TestBuffer_edge_fromEmpty(t *testing.T) {
	b := NewBuffer([]byte{})
	if len(b.Bytes()) != 0 {
		t.Fatal("non-empty Bytes")
	}
}

func TestBuffer_edge_hugeAppendAfterTinyPrefix(t *testing.T) {
	// len(b)+n must exceed 2*cap(old); realloc must not truncate prefix.
	backing := make([]byte, 1, 1000)
	backing[0] = 0x01
	b := NewBuffer(backing)
	dst := b.Append(3000)
	for i := range dst {
		dst[i] = 0x02
	}
	want := append([]byte{0x01}, bytes.Repeat([]byte{0x02}, 3000)...)
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("len %d, want %d", len(b.Bytes()), len(want))
	}
}

func TestBuffer_corruption_reallocDoesNotMutateCallerSlice(t *testing.T) {
	backing := []byte{'x', 'y'} // len == cap
	b := NewBuffer(backing)
	copy(b.Append(3), []byte("abc"))
	if string(backing) != "xy" {
		t.Fatalf("caller slice mutated: %q", backing)
	}
}

func TestBuffer_corruption_reallocPreservesPriorBytes(t *testing.T) {
	var b Buffer
	copy(b.Append(4), []byte("dead"))
	copy(b.Append(4), []byte("beef"))
	want := []byte("deadbeef")
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("got %q want %q", b.Bytes(), want)
	}
}

func TestBuffer_corruption_appendViewAliasesContent(t *testing.T) {
	var b Buffer
	p := b.Append(2)
	p[0], p[1] = 1, 2
	if b.Bytes()[0] != 1 || b.Bytes()[1] != 2 {
		t.Fatal("write through Append slice not visible in Bytes")
	}
}

func TestBuffer_corruption_resetThenAppend(t *testing.T) {
	var b Buffer
	copy(b.Append(2), []byte{1, 2})
	b.Reset()
	copy(b.Append(1), []byte{3})
	if !bytes.Equal(b.Bytes(), []byte{3}) {
		t.Fatalf("got %v", b.Bytes())
	}
}

func TestBuffer_corruption_writeThenZero(t *testing.T) {
	var b Buffer
	copy(b.Append(2), []byte{1, 2})
	b.Zero()
	b.written = 2 // move the written position to the second byte
	if !bytes.Equal(b.Bytes(), []byte{0, 0}) {
		t.Fatalf("got %v", b.Bytes())
	}
}
