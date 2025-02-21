package icmp

// Helper methods for ICMP sequence wraparound handling
const maxICMPSeq = 65535 // Maximum value for 16-bit sequence number

// Constants for uint32 sequence number handling
const (
	maxUint32Seq  = ^uint32(0)
	halfUint32Seq = uint32(1) << 31
	halfUint16Seq = uint16(1) << 15 // 32768: Half of uint16 sequence space
)

// isUint16SeqHigher returns true if a is higher than b, accounting for wraparound
func isUint16SeqHigher(a, b uint32) bool {
	if a == b {
		return false
	}
	return uint16(a-b) < halfUint16Seq
}

// uint16SeqDiff returns the difference between two sequence numbers, accounting for wraparound
func uint16SeqDiff(a, b uint32) uint32 {
	return uint32(uint16(a) - uint16(b)) // Natural wraparound handles everything!
}

// nextUint16Seq returns the next sequence number, handling wraparound
func nextUint16Seq(seq uint32) uint32 {
	return uint32(uint16(seq + 1))
}

// isSeqInWindow returns true if the sequence number is within the valid window
func isUint16SeqInWindow(seq, start, end uint32) bool {
	// Normalize seq relative to start
	normalizedSeq := uint16(seq - start)
	normalizedEnd := uint16(end - start)
	return normalizedSeq <= normalizedEnd
}

// isUint32SeqHigher returns true if a is higher than b, accounting for wraparound
func isUint32SeqHigher(a, b uint32) bool {
	if a == b {
		return false
	}
	return (a - b) < halfUint32Seq
}

// uint32SeqDiff returns the difference between two sequence numbers, accounting for wraparound
func uint32SeqDiff(a, b uint32) uint32 {
	return a - b // Natural wraparound handles everything!
}

// nextUint32Seq returns the next sequence number, handling wraparound
func nextUint32Seq(seq uint32) uint32 {
	return seq + 1 // Natural wraparound of uint32
}

// isUint32SeqInWindow returns true if the sequence number is within the valid window,
// properly handling wraparound cases. The window is defined as [start, end] inclusive.
func isUint32SeqInWindow(seq, start, end uint32) bool {
	// Normalize seq relative to start
	normalizedSeq := seq - start
	normalizedEnd := end - start
	return normalizedSeq <= normalizedEnd
}
