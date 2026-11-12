package queue

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// drainHow is how we empty the queue.
type drainHow int

const (
	drainPop drainHow = iota
	drainPopAll
	drainTryPop
	drainTryPopAll
)

func (d drainHow) String() string {
	switch d {
	case drainPop:
		return "Pop"
	case drainPopAll:
		return "PopAll"
	case drainTryPop:
		return "TryPop"
	case drainTryPopAll:
		return "TryPopAll"
	default:
		return "unknown"
	}
}

func drainFIFO(t *testing.T, q *FIFO[int], how drainHow, n int) []int {
	t.Helper()
	switch how {
	case drainPop:
		out := make([]int, n)
		for i := 0; i < n; i++ {
			out[i] = q.Pop()
		}
		return out

	case drainPopAll:
		return q.PopAll()

	case drainTryPop:
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			got, empty, closed := q.TryPop()
			if closed {
				t.Fatal("TryPop: unexpected closed")
			}
			out = append(out, got)
			wantEmpty := i == n-1
			if empty != wantEmpty {
				t.Fatalf("TryPop[%d]: empty=%v, want %v", i, empty, wantEmpty)
			}
		}
		return out

	case drainTryPopAll:
		got, empty, closed := q.TryPopAll()
		if closed {
			t.Fatal("TryPopAll: unexpected closed")
		}
		if empty {
			t.Fatal("TryPopAll: unexpected empty")
		}
		return got

	default:
		t.Fatalf("unknown drainHow %d", how)
		return nil
	}
}

func TestFIFOOrder(t *testing.T) {
	drains := []drainHow{drainPop, drainPopAll, drainTryPop, drainTryPopAll}

	cases := []struct {
		name   string
		length int
		items  []int
	}{
		{"single", 4, []int{7}},
		{"few", 8, []int{1, 2, 3}},
		{"fill exact capacity", 4, []int{10, 20, 30, 40}},
		{"with duplicates", 8, []int{1, 1, 2, 2, 3}},
	}

	for _, tc := range cases {
		for _, how := range drains {
			t.Run(tc.name+"/"+how.String(), func(t *testing.T) {
				q := NewFIFO[int](tc.length)
				for _, item := range tc.items {
					if err := q.Push(item); err != nil {
						t.Fatalf("Push(%d): %v", item, err)
					}
				}
				got := drainFIFO(t, q, how, len(tc.items))
				if !slices.Equal(got, tc.items) {
					t.Fatalf("got %v, want %v", got, tc.items)
				}
			})
		}
	}
}

// Ring cursors wrap once we drain some slots and push again.
func TestFIFORingWrapOrder(t *testing.T) {
	drains := []drainHow{drainPop, drainPopAll, drainTryPop, drainTryPopAll}

	cases := []struct {
		name          string
		length        int
		first         []int
		popCount      int
		second        []int
		wantRemaining []int
	}{
		{
			name:          "wrap by two",
			length:        4,
			first:         []int{1, 2, 3, 4},
			popCount:      2,
			second:        []int{5, 6},
			wantRemaining: []int{3, 4, 5, 6},
		},
		{
			name:          "wrap full cycle",
			length:        3,
			first:         []int{1, 2, 3},
			popCount:      3,
			second:        []int{4, 5, 6},
			wantRemaining: []int{4, 5, 6},
		},
	}

	for _, tc := range cases {
		for _, how := range drains {
			t.Run(tc.name+"/"+how.String(), func(t *testing.T) {
				q := NewFIFO[int](tc.length)
				for _, item := range tc.first {
					if err := q.Push(item); err != nil {
						t.Fatalf("Push(%d): %v", item, err)
					}
				}
				for i := 0; i < tc.popCount; i++ {
					_ = q.Pop()
				}
				for _, item := range tc.second {
					if err := q.Push(item); err != nil {
						t.Fatalf("Push(%d): %v", item, err)
					}
				}
				got := drainFIFO(t, q, how, len(tc.wantRemaining))
				if !slices.Equal(got, tc.wantRemaining) {
					t.Fatalf("got %v, want %v", got, tc.wantRemaining)
				}
			})
		}
	}
}

func TestFIFOClose(t *testing.T) {
	t.Run("Push returns ErrClosed", func(t *testing.T) {
		q := NewFIFO[int](4)
		q.Close()
		if err := q.Push(1); !errors.Is(err, ErrClosed) {
			t.Fatalf("Push after Close: got %v, want ErrClosed", err)
		}
	})

	t.Run("TryPop on empty closed", func(t *testing.T) {
		q := NewFIFO[int](4)
		q.Close()
		_, empty, closed := q.TryPop()
		if !empty || !closed {
			t.Fatalf("empty=%v closed=%v, want true/true", empty, closed)
		}
	})

	t.Run("TryPopAll on empty closed", func(t *testing.T) {
		q := NewFIFO[int](4)
		q.Close()
		_, empty, closed := q.TryPopAll()
		if !empty || !closed {
			t.Fatalf("empty=%v closed=%v, want true/true", empty, closed)
		}
	})

	t.Run("Pop on empty closed returns zero", func(t *testing.T) {
		q := NewFIFO[int](4)
		q.Close()
		if got := q.Pop(); got != 0 {
			t.Fatalf("Pop = %d, want 0", got)
		}
	})

	t.Run("blocked Push unblocks with ErrClosed", func(t *testing.T) {
		q := NewFIFO[int](1)
		if err := q.Push(1); err != nil {
			t.Fatal(err)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- q.Push(2) // blocks until Close
		}()

		// Let the goroutine reach Wait.
		time.Sleep(20 * time.Millisecond)
		q.Close()

		select {
		case err := <-errCh:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("blocked Push: got %v, want ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked Push did not unblock after Close")
		}
	})
}

func TestFIFOPushUnblocksWhenNotFull(t *testing.T) {
	q := NewFIFO[int](2)
	if err := q.Push(1); err != nil {
		t.Fatal(err)
	}
	if err := q.Push(2); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- q.Push(3) // blocks while full
	}()

	time.Sleep(20 * time.Millisecond)
	if got := q.Pop(); got != 1 {
		t.Fatalf("Pop = %d, want 1", got)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Push after Pop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Push did not unblock after Pop")
	}

	got := []int{q.Pop(), q.Pop()}
	want := []int{2, 3}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFIFOWREDDrop(t *testing.T) {
	// max threshold 0 and maxDP 1 → every Push is dropped.
	q := NewFIFO[int](8).WithWRED(9, 1.0, 0, 0)
	if err := q.Push(1); !errors.Is(err, ErrWREDDropped) {
		t.Fatalf("Push: got %v, want ErrWREDDropped", err)
	}
	_, empty, _ := q.TryPop()
	if !empty {
		t.Fatal("queue should still be empty after WRED drop")
	}
}

func TestFIFOSPSCOrder(t *testing.T) {
	const n = 1000
	q := NewFIFO[int](16)

	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			if err := q.Push(i); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	for i := 0; i < n; i++ {
		got := q.Pop()
		if got != i {
			t.Fatalf("Pop = %d, want %d", got, i)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Push: %v", err)
	}
}
