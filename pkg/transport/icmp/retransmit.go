package icmp

import (
	"encoding/binary"
	"sync"
)

type packetEntry struct {
	seq  uint32
	data *rawSockBuffer
}

type RetransmitQueue struct {
	sync.Mutex
	packets     []packetEntry
	clearMemory func(m *rawSockBuffer)
}

func NewRetransmitQueue(clearMemory func(m *rawSockBuffer)) *RetransmitQueue {
	if clearMemory == nil {
		clearMemory = func(m *rawSockBuffer) {}
	}
	return &RetransmitQueue{
		packets:     make([]packetEntry, 0),
		clearMemory: clearMemory,
	}
}

func (q *RetransmitQueue) Put(data *rawSockBuffer) {
	if data.len-(data.po+8) <= 8 {
		q.clearMemory(data)
		return // Ignore packets that are too small
	}

	q.Lock()

	seq := binary.BigEndian.Uint32(data.b[data.po+8 : data.po+8+4])

	// transport.Logger.Infof("Put() packet with seq %d, packets in queue: %d", seq, len(q.packets))

	if len(q.packets) > 0 && q.packets[len(q.packets)-1].seq >= seq {
		q.clearMemory(data)
		q.Unlock()
		return
	}

	q.packets = append(q.packets, packetEntry{
		seq:  seq,
		data: data,
	})
	q.Unlock()
}

func (q *RetransmitQueue) GetPacket(seq uint32) []byte {
	q.Lock()
	for _, entry := range q.packets {
		if entry.seq == seq {
			q.Unlock()
			return entry.data.b[entry.data.po+8 : entry.data.len]
		}
	}
	q.Unlock()
	return nil
}

func (q *RetransmitQueue) DeleteUntil(seq uint32) uint32 {
	q.Lock()
	if len(q.packets) == 0 {
		q.Unlock()
		return 0
	}

	var (
		deletedBytes uint32
		foundIdx     = -1
	)

	// Find target sequence and calculate deleted bytes
	for i, entry := range q.packets {
		if entry.seq == seq {
			foundIdx = i
			break
		}
		if entry.seq > seq {
			foundIdx = i - 1
			break
		}
		deletedBytes += uint32(entry.data.len - entry.data.po - eHeaderSize)
	}

	if foundIdx == -1 {
		// If we didn't find the sequence, we should keep all packets
		q.Unlock()
		return deletedBytes
	}

	// transport.Logger.Infof("Deleting packets up to seq %d, packets left in queue: %d", seq, len(q.packets))

	// Clear memory from the start of packets up until the found index
	for i := 0; i < foundIdx; i++ {
		q.clearMemory(q.packets[i].data)
	}

	// Update packets slice
	remainingEntries := len(q.packets) - foundIdx
	if remainingEntries > 0 {
		copy(q.packets, q.packets[foundIdx:])
	}
	q.packets = q.packets[:remainingEntries]

	q.Unlock()
	return deletedBytes
}

func (q *RetransmitQueue) Len() uint32 {
	q.Lock()
	var totalLen uint32
	for _, entry := range q.packets {
		totalLen += uint32(entry.data.len - entry.data.po - eHeaderSize)
	}
	q.Unlock()
	return totalLen
}

func (q *RetransmitQueue) Clear() {
	q.Lock()
	q.packets = q.packets[:0]
	q.Unlock()
}

// RangeFrom calls the provided function for each packet in the queue,
// starting from the given sequence number. If seq is 0, starts from the first packet.
// The function is called with: current packet sequence number, next packet sequence number
// (or 0 if there is no next packet), and the current packet data.
// If the callback returns false, iteration stops.
func (q *RetransmitQueue) RangeFrom(seq uint32, fn func(seq uint32, nextSeq uint32, data []byte) bool) {
	q.Lock()
	if len(q.packets) == 0 {
		q.Unlock()
		return
	}

	var (
		found    = false
		startIdx = 0
	)
	// Find starting position
	for i, entry := range q.packets {
		if entry.seq == seq {
			startIdx = i
			found = true
			break
		}
		if entry.seq > seq {
			break
		}
	}

	if !found {
		q.Unlock()
		return
	}

	// Iterate through packets
	for i := startIdx; i < len(q.packets); i++ {
		entry := q.packets[i]

		// Get next sequence number (0 if this is the last packet)
		nextSeq := uint32(0)
		if i+1 < len(q.packets) {
			nextSeq = q.packets[i+1].seq
		}

		if !fn(entry.seq, nextSeq, entry.data.b[entry.data.po+8:entry.data.len]) {
			break
		}
	}
	q.Unlock()
}
