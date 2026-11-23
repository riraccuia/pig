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

import (
	"net"
)

// CloseWrite shuts down the sending direction. A FIN follows the queued data.
func (c *Conn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shutdownWrite()
	return nil
}

// Close closes both directions. Queued data and the FIN handshake complete
// in the background, like a kernel socket.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readClosed {
		return nil
	}
	c.readClosed = true
	c.recvBuf.release()
	c.cond.Broadcast()
	c.shutdownWrite()
	c.armOrphanTimeout()
	return nil
}

// shutdownWrite implements the CLOSE call of RFC 9293 §3.10.4.
func (c *Conn) shutdownWrite() {
	if c.writeClosed {
		return
	}
	c.writeClosed = true
	c.cond.Broadcast()
	switch c.state {
	case StateSynSent:
		c.closeWith(net.ErrClosed)
		return
	case StateSynReceived, StateEstablished:
		c.setState(StateFinWait1)
	case StateCloseWait:
		c.setState(StateLastAck)
	default:
		return
	}
	c.finQueued = true
	c.trySend()
}

// abort implements the ABORT call of RFC 9293 §3.10.5.
func (c *Conn) abort(err error) {
	if c.state.synchronized() || c.state == StateSynReceived {
		c.sendRst(c.sndNxt)
	}
	c.closeWith(err)
}

func (c *Conn) closeWith(err error) {
	if c.state == StateClosed {
		return
	}
	if c.err == nil {
		c.err = err
	}
	c.setState(StateClosed)
}

// release frees the control block once CLOSED is reached. The receive buffer
// is kept: the application may still read data that arrived before CLOSED,
// and Close releases it.
func (c *Conn) release() {
	c.rtoTimer.stop()
	c.persistTimer.stop()
	c.delAckTimer.stop()
	c.timeWaitTimer.stop()
	c.finWait2Timer.stop()
	c.readDeadline.stop()
	c.writeDeadline.stop()
	c.ooq.clear()
	c.sendBuf.release()
	c.signalReady()
	c.cond.Broadcast()
	c.stack.removeConn(c)
}

// armTimeWait (re)starts the 2*MSL TIME-WAIT timer (RFC 9293 §3.10.7.4).
func (c *Conn) armTimeWait() {
	c.timeWaitTimer.arm(c, 2*c.stack.opts.MSL, func() { c.closeWith(nil) })
}

// armOrphanTimeout bounds FIN-WAIT-2 for connections the application closed,
// since nothing else would ever reclaim them if the peer never sends FIN.
func (c *Conn) armOrphanTimeout() {
	if c.state != StateFinWait2 || !c.readClosed {
		return
	}
	c.finWait2Timer.arm(c, c.stack.opts.FinWait2Timeout, func() { c.closeWith(nil) })
}
