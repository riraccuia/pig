package icmp

import (
	"sync"
	"sync/atomic"
)

type FlightCounter struct {
	sync.Mutex
	cond *sync.Cond
	cwnd *atomic.Uint32
	bc   uint32
}

func NewFlightCounter(cwnd *atomic.Uint32) *FlightCounter {
	fc := &FlightCounter{cwnd: cwnd}
	fc.cond = sync.NewCond(&fc.Mutex)
	return fc
}

func (fc *FlightCounter) Load() (fs uint32) {
	fc.Lock()
	fs = fc.bc
	fc.Unlock()
	return
}

func (fc *FlightCounter) Add(num uint32) {
	if num <= 0 {
		return
	}
	fc.Lock()
	fc.bc += num
	fc.Unlock()
}

func (fc *FlightCounter) Sub(num uint32) {
	if num <= 0 {
		return
	}
	fc.Lock()
	if num > fc.bc {
		fc.bc = 0
		fc.Unlock()
		fc.cond.Broadcast()
		return
	}
	fc.bc -= num
	fc.Unlock()
	fc.cond.Broadcast()
}

func (fc *FlightCounter) WaitCwnd() {
	fc.Lock()
	if fc.bc == 0 {
		fc.Unlock()
		return
	}
	for fc.bc >= fc.cwnd.Load() {
		fc.cond.Wait()
	}
	fc.Unlock()
}
