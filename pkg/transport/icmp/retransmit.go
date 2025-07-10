package icmp

import (
	"sync"
)

// RetransmitQueue is a queue of packets that need to be retransmitted
// It is used to store packets that have been sent but not yet acknowledged
// and retransmit them when necessary.
// It can also be used to temporarily store packets that have been received
// out of order, to recover from losses after the lost data has been retransmitted.
type RetransmitQueue struct {
	sync.Mutex
	packets     []*Packet
	clearMemory func(m []byte)
}

func NewRetransmitQueue(clearMemory func(m []byte)) *RetransmitQueue {
	if clearMemory == nil {
		clearMemory = func(m []byte) {}
	}
	return &RetransmitQueue{
		packets:     make([]*Packet, 0),
		clearMemory: clearMemory,
	}
}

// Put simply appends a packet to the queue, unless that packet
// has a smaller sequence number than the last packet in the queue.
// This is the best method to use for retransmit queues.
func (q *RetransmitQueue) Put(packet *Packet) {
	if len(packet.Data) == 0 {
		q.clearMemory(packet.buffer)
		return // Ignore packets that are too small
	}

	q.Lock()

	if len(q.packets) == 0 {
		q.packets = append(q.packets, packet)
		q.Unlock()
		return
	}

	lastPacket := q.packets[len(q.packets)-1]

	if lastPacket.PacketSeq >= packet.PacketSeq {
		q.clearMemory(packet.buffer)
		q.Unlock()
		return
	}

	q.packets = append(q.packets, packet)
	q.Unlock()
}

func (q *RetransmitQueue) GetPacket(seq uint32) *Packet {
	q.Lock()
	for _, entry := range q.packets {
		if entry.PacketSeq == seq {
			pkt := entry
			q.Unlock()
			return pkt
		}
	}
	q.Unlock()
	return nil
}

// DeleteUntil deletes all packets up until the given sequence number.
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
		if entry.PacketSeq == seq {
			foundIdx = i
			break
		}
		if entry.PacketSeq > seq {
			//if i-1 >= 0 {
			//fmt.Printf("DeleteUntil: seq: %d, prev_entry.seq: %d, prev_entry.len: %d, next.seq: %d, foundEntry: %s\n", seq, q.packets[i-1].PacketSeq, len(q.packets[i-1].Data), q.packets[i-1].PacketSeq+uint32(len(q.packets[i-1].Data)), q.packets[i].PigPacket())
			//}
			foundIdx = i //- 1
			break
		}
		deletedBytes += uint32(len(entry.Data))
	}

	if foundIdx == -1 {
		// If we didn't find the sequence, we should keep all packets
		q.Unlock()
		return deletedBytes
	}

	// transport.Logger.Infof("Deleting packets up to seq %d, packets left in queue: %d", seq, len(q.packets))

	// Clear memory from the start of packets up until the found index
	for i := 0; i < foundIdx; i++ {
		q.clearMemory(q.packets[i].buffer)
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
		totalLen += uint32(len(entry.Data))
	}
	q.Unlock()
	return totalLen
}

func (q *RetransmitQueue) Clear() {
	q.Lock()
	for _, entry := range q.packets {
		q.clearMemory(entry.buffer)
	}
	q.packets = q.packets[:0]
	q.Unlock()
}

// RangeFrom calls the provided function for each packet in the queue,
// starting from the given sequence number. If seq is 0, starts from the first packet.
// The function is called with: current packet sequence number, next packet sequence number
// (or 0 if there is no next packet), and the current packet data.
// If the callback returns false, iteration stops.
func (q *RetransmitQueue) RangeFrom(seq uint32, fn func(packet *Packet, nextSeq uint32) bool) {
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
		if entry.PacketSeq == seq {
			startIdx = i
			found = true
			break
		}
		if entry.PacketSeq > seq {
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
			nextSeq = q.packets[i+1].PacketSeq
		}

		if !fn(entry, nextSeq) {
			break
		}
	}
	q.Unlock()
}
