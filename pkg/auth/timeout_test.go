package auth

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type deadlineRW struct {
	bytes.Buffer
	deadline time.Time
	calls    int
}

func (r *deadlineRW) SetDeadline(t time.Time) error {
	r.deadline = t
	r.calls++
	return nil
}

func TestBindAuthTimeout(t *testing.T) {
	const skew = 200 * time.Millisecond

	t.Run("zero_duration_uses_default", func(t *testing.T) {
		rw := &bytes.Buffer{}
		before := time.Now()
		ctx, cancel := BindAuthTimeout(context.Background(), 0, rw)
		defer cancel()

		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected context deadline")
		}
		want := before.Add(DefaultAuthTimeout)
		if dl.Before(want.Add(-skew)) || dl.After(want.Add(skew)) {
			t.Fatalf("deadline %v, want ~%v (±%v)", dl, want, skew)
		}
	})

	t.Run("positive_duration_sets_context_deadline", func(t *testing.T) {
		rw := &bytes.Buffer{}
		d := 5 * time.Second
		before := time.Now()
		ctx, cancel := BindAuthTimeout(context.Background(), d, rw)
		defer cancel()

		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected context deadline")
		}
		want := before.Add(d)
		if dl.Before(want.Add(-skew)) || dl.After(want.Add(skew)) {
			t.Fatalf("deadline %v, want ~%v (±%v)", dl, want, skew)
		}
	})

	t.Run("setdeadline_when_supported", func(t *testing.T) {
		rw := &deadlineRW{}
		d := 3 * time.Second
		before := time.Now()
		_, cancel := BindAuthTimeout(context.Background(), d, rw)
		defer cancel()

		if rw.calls != 1 {
			t.Fatalf("SetDeadline calls = %d, want 1", rw.calls)
		}
		want := before.Add(d)
		if rw.deadline.Before(want.Add(-skew)) || rw.deadline.After(want.Add(skew)) {
			t.Fatalf("conn deadline %v, want ~%v (±%v)", rw.deadline, want, skew)
		}
	})

	t.Run("cancel_clears_deadline_and_context", func(t *testing.T) {
		rw := &deadlineRW{}
		ctx, cancel := BindAuthTimeout(context.Background(), time.Minute, rw)
		cancel()

		if !rw.deadline.IsZero() {
			t.Fatalf("deadline after cancel = %v, want zero", rw.deadline)
		}
		if rw.calls != 2 {
			t.Fatalf("SetDeadline calls = %d, want 2 (set + clear)", rw.calls)
		}
		if err := ctx.Err(); err != context.Canceled {
			t.Fatalf("ctx.Err() = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("no_setdeadline_still_bounds_context", func(t *testing.T) {
		rw := &bytes.Buffer{} // ReadWriter without SetDeadline
		ctx, cancel := BindAuthTimeout(context.Background(), 30*time.Millisecond, rw)
		defer cancel()

		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != context.DeadlineExceeded {
				t.Fatalf("ctx.Err() = %v, want %v", err, context.DeadlineExceeded)
			}
		case <-time.After(time.Second):
			t.Fatal("context did not expire")
		}
	})
}
