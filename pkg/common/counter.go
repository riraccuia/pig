package common

import (
	"context"
	"sync/atomic"
	"time"
)

// DelayedCounterProcessor accumulates counter values and processes them at regular intervals.
// It supports both fixed intervals and exponential backoff using Fibonacci sequence.
// The processor maintains two atomic counters (c1, c2) that can be incremented concurrently
// and periodically calls the provided callback function with their values.
type DelayedCounterProcessor struct {
	delays    []time.Duration
	baseDelay time.Duration
	backoff   bool
	c1, c2    atomic.Uint64
	cb        func(c1, c2 *atomic.Uint64)
}

// NewDelayedCounterProcessor creates a new DelayedCounterProcessor with a default
// delay of 1 second and the provided callback function.
// The callback function is called periodically with the current counter values.
func NewDelayedCounterProcessor(cb func(c1, c2 *atomic.Uint64)) *DelayedCounterProcessor {
	return &DelayedCounterProcessor{
		baseDelay: time.Second,
		cb:        cb,
	}
}

// WithBackoff configures the processor to use exponential backoff based on the Fibonacci sequence.
// It generates a sequence of delays starting from startDelay and not exceeding maxDelay.
// Returns the processor instance for method chaining.
func (l *DelayedCounterProcessor) WithBackoff(startDelay, maxDelay time.Duration) *DelayedCounterProcessor {
	// fibo generates the Fibonacci sequence
	fibo := func(yield func(u int) bool) {
		f0, f1 := int(startDelay), int(startDelay*2)
		for yield(f0) {
			f0, f1 = f1, f0+f1
		}
	}
	for x := range fibo {
		if x >= int(maxDelay) {
			break
		}
		l.delays = append(l.delays, time.Duration(x))
	}
	l.backoff = true
	return l
}

// SetDelay sets the base delay between processing cycles.
// This is used when backoff is not enabled or as the initial delay after processing.
func (l *DelayedCounterProcessor) SetDelay(delay time.Duration) {
	l.baseDelay = delay
}

// nextDelay returns the next delay duration based on the current position
// and whether backoff is enabled.
func (l *DelayedCounterProcessor) nextDelay(pos int) time.Duration {
	if l.backoff {
		return l.delays[pos]
	}
	return l.baseDelay
}

// Start begins the counter processing in a separate goroutine.
// The processor will run until the provided context is canceled.
func (l *DelayedCounterProcessor) Start(ctx context.Context) {
	go l.start(ctx)
}

// start is the internal implementation of the processing loop.
// It periodically checks the counters and calls the callback function
// when there are values to process.
func (l *DelayedCounterProcessor) start(ctx context.Context) {
	pos := 0
	timer := time.NewTimer(l.baseDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if l.c1.Load() == 0 {
				timer.Reset(l.nextDelay(pos))
				pos = (pos + 1) % len(l.delays)
				continue
			}
			l.cb(&l.c1, &l.c2)
			l.c1.Store(0)
			l.c2.Store(0)
			timer.Reset(l.baseDelay)
		}
	}
}

// Incr atomically adds the provided values to the internal counters.
// This method is safe to call from multiple goroutines.
func (l *DelayedCounterProcessor) Incr(c1, c2 uint64) {
	l.c1.Add(c1)
	l.c2.Add(c2)
}
