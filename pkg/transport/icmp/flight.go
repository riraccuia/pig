package icmp

import (
	"sync"
	"sync/atomic"
)

type FlightCounter struct {
	sync.Mutex
	cond           *sync.Cond
	cwnd           *atomic.Uint32
	sendWindowSize uint32
	bc             uint32
}

func NewFlightCounter(cwnd *atomic.Uint32, sendWindowSize uint32) *FlightCounter {
	fc := &FlightCounter{cwnd: cwnd, sendWindowSize: sendWindowSize}
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
		fc.cond.Signal()
		fc.Unlock()
		return
	}
	fc.bc -= num
	fc.cond.Signal()
	fc.Unlock()
}

func (fc *FlightCounter) WaitCwnd(emss uint32) {
	fc.Lock()
	for fc.bc > 0 && (fc.bc >= (fc.cwnd.Load()-emss) || (fc.bc >= (fc.sendWindowSize - emss))) {
		fc.cond.Wait()
	}
	fc.Unlock()
}
