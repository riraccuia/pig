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

package jwt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestReadTokenContext(t *testing.T) {
	t.Run("returns_framed_token", func(t *testing.T) {
		const want = "abc"
		var buf bytes.Buffer
		if err := SendToken(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadTokenContext(context.Background(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("context_timeout_while_blocked", func(t *testing.T) {
		pr, pw := io.Pipe()
		defer pw.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()

		_, err := ReadTokenContext(ctx, pr)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want %v", err, context.DeadlineExceeded)
		}
	})

	t.Run("propagates_read_error", func(t *testing.T) {
		pr, pw := io.Pipe()
		_ = pw.Close() // EOF on read

		_, err := ReadTokenContext(context.Background(), pr)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want %v", err, io.EOF)
		}
	})
}
