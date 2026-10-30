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
