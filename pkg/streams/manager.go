package streams

import (
	"net"
	"sync/atomic"

	"github.com/riraccuia/pig/pkg/transport"
)

// StreamManager provides thread-safe management of network streams
type StreamManager struct {
	lock    int32
	streams []transport.Stream
}

// New creates a new StreamManager instance
func New() *StreamManager {
	return &StreamManager{
		streams: make([]transport.Stream, 0),
	}
}

// acquireLock atomically acquires the lock
func (sm *StreamManager) acquireLock() {
	for !sm.tryLock() {
		// Spin until lock is acquired
	}
}

// tryLock attempts to acquire the lock
func (sm *StreamManager) tryLock() bool {
	return atomic.CompareAndSwapInt32(&sm.lock, 0, 1)
}

// releaseLock releases the lock
func (sm *StreamManager) releaseLock() {
	atomic.StoreInt32(&sm.lock, 0)
}

// Add appends a new stream to the manager
func (sm *StreamManager) Add(stream transport.Stream) {
	sm.acquireLock()
	sm.streams = append(sm.streams, stream)
	sm.releaseLock()
}

// Remove removes a stream from the manager
func (sm *StreamManager) Remove(stream transport.Stream) {
	sm.acquireLock()
	for i, s := range sm.streams {
		if s == stream {
			lastIdx := len(sm.streams) - 1
			sm.streams[i] = sm.streams[lastIdx]
			sm.streams[lastIdx] = nil
			sm.streams = sm.streams[:lastIdx]
			break
		}
	}
	sm.releaseLock()
}

// SelectByIPAndPort selects a stream based on IP address and port for load balancing
func (sm *StreamManager) SelectByIPAndPort(ip net.IP, port uint16) transport.Stream {
	sm.acquireLock()
	numStreams := len(sm.streams)
	if numStreams == 0 {
		sm.releaseLock()
		return nil
	}
	if numStreams == 1 {
		stream := sm.streams[0]
		sm.releaseLock()
		return stream
	}
	ip = ip.To4()
	// Combine IP and port into a single value for better distribution
	ipInt := uint32(ip[3]) | uint32(ip[2])<<8 | uint32(ip[1])<<16 | uint32(ip[0])<<24
	// Use combined value for stream selection
	streamIndex := (uint32(port) ^ ipInt) % uint32(numStreams)
	stream := sm.streams[streamIndex]
	sm.releaseLock()
	return stream
}

// CloseAll closes all streams and clears the manager
func (sm *StreamManager) CloseAll() {
	sm.acquireLock()
	for _, stream := range sm.streams {
		stream.Close()
	}
	sm.streams = sm.streams[:0]
	sm.releaseLock()
}

// Count returns the current number of streams
func (sm *StreamManager) Count() int {
	sm.acquireLock()
	count := len(sm.streams)
	sm.releaseLock()
	return count
}
