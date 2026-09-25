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
	"errors"
	"sync"

	"github.com/riraccuia/pig/pkg/queue/wred"
)

var (
	ErrDropped     = errors.New("dropped")
	ErrWREDDropped = errors.New("wred dropped")
	ErrClosed      = errors.New("closed")
)

type FIFO[T any] struct {
	sync.Mutex
	cond    *sync.Cond
	queue   []T
	length  int
	elems   int
	rCursor int
	wCursor int
	wred    *wred.WRED
	closed  bool
}

func NewFIFO[T any](length int) *FIFO[T] {
	f := &FIFO[T]{
		queue:   make([]T, length),
		length:  length,
		rCursor: 0,
		wCursor: 0,
	}
	f.cond = sync.NewCond(&f.Mutex)
	return f
}

func (f *FIFO[T]) WithWRED(factor, dropProbability, threshold float64) *FIFO[T] {
	var err error
	f.wred, err = wred.NewWRED(f.length, factor, dropProbability, threshold)
	if err != nil {
		panic(err)
	}
	return f
}

func (f *FIFO[T]) Push(item T) error {
	f.Lock()
	err := f.push(item)
	f.Unlock()
	return err
}

func (f *FIFO[T]) push(item T) error {
	if f.closed {
		return ErrClosed
	}
	if f.elems == f.length {
		// tail drop
		return ErrDropped
	}
	if f.wred != nil {
		f.wred.Update(float64(f.elems))
		if f.wred.IsDrop() {
			return ErrWREDDropped
		}
	}
	f.queue[f.wCursor] = item
	f.wCursor = (f.wCursor + 1) % f.length
	prevElems := f.elems
	f.elems++
	if prevElems > 0 {
		return nil
	}
	f.cond.Signal()
	return nil
}

func (f *FIFO[T]) Pop() T {
	f.Lock()
	val := f.pop()
	f.Unlock()
	return val
}

func (f *FIFO[T]) PopAll() []T {
	f.Lock()
	val := f.popAll()
	f.Unlock()
	return val
}

func (f *FIFO[T]) TryPop() (val T, empty bool, closed bool) {
	f.Lock()
	closed = f.closed
	if f.elems == 0 {
		f.Unlock()
		return zero[T](), true, closed
	}
	val = f.pop()
	elems := f.elems
	f.Unlock()
	return val, elems == 0, closed
}

func (f *FIFO[T]) TryPopAll() (vals []T, empty bool, closed bool) {
	f.Lock()
	closed = f.closed
	if f.elems == 0 {
		f.Unlock()
		return nil, true, closed
	}
	vals = f.popAll()
	f.Unlock()
	return vals, len(vals) == 0, closed
}

func (f *FIFO[T]) pop() T {
	for f.elems == 0 {
		if f.closed {
			return zero[T]()
		}
		f.cond.Wait()
	}
	item := f.queue[f.rCursor]
	f.queue[f.rCursor] = zero[T]()
	f.rCursor = (f.rCursor + 1) % f.length
	f.elems--
	return item
}

func (f *FIFO[T]) popAll() []T {
	for f.elems == 0 {
		if f.closed {
			return nil
		}
		f.cond.Wait()
	}
	n := f.elems
	items := make([]T, n)
	for i := 0; i < n; i++ {
		items[i] = f.queue[f.rCursor]
		f.queue[f.rCursor] = zero[T]()
		f.rCursor = (f.rCursor + 1) % f.length
	}
	f.elems = 0
	return items
}

func (f *FIFO[T]) Close() {
	f.Lock()
	f.closed = true
	f.Unlock()
	f.cond.Broadcast()
}
