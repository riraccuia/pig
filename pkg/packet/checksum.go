package packet

func (p IPv4Packet) UpdateChecksum() {
	if p.TotalLength() > len(p) {
		return
	}

	// Update IP header checksum
	p.updateIPChecksum()

	// Update transport layer checksum based on protocol
	switch p.Protocol() {
	case 1: // ICMP
		p.updateICMPChecksum()
	case 6: // TCP
		p.updateTCPChecksum()
	case 17: // UDP
		p.updateUDPChecksum()
	}
}

func (p IPv4Packet) updateIPChecksum() {
	// Reset checksum field
	p[10] = 0
	p[11] = 0

	// Calculate new checksum for IP header only
	var sum uint32
	headerLen := p.PayloadOffset()
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(p[i]) << 8
		sum += uint32(p[i+1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	checksum := ^uint16(sum)
	p[10] = byte(checksum >> 8)
	p[11] = byte(checksum)
}

func (p IPv4Packet) updateTCPChecksum() {
	offset := p.PayloadOffset()
	tcpLen := p.TotalLength() - offset

	// Reset TCP checksum field (offset + 16 is the TCP checksum location)
	p[offset+16] = 0
	p[offset+17] = 0

	// Calculate pseudo-header sum
	sum := p.pseudoHeaderSum(tcpLen)

	// Add TCP header and payload
	for i := 0; i < tcpLen-1; i += 2 {
		sum += uint32(p[offset+i]) << 8
		sum += uint32(p[offset+i+1])
	}

	if tcpLen%2 == 1 {
		sum += uint32(p[offset+tcpLen-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	checksum := ^uint16(sum)
	p[offset+16] = byte(checksum >> 8)
	p[offset+17] = byte(checksum)
}

func (p IPv4Packet) updateUDPChecksum() {
	offset := p.PayloadOffset()

	// Validate we have enough space for UDP header (8 bytes)
	if len(p) < offset+8 {
		return
	}

	// Get UDP length and validate it
	udpLen := int(uint16(p[offset+4]) | uint16(p[offset+5])<<8) //binary.BigEndian.Uint16(p[offset+4 : offset+6])
	if offset+udpLen > len(p) {
		return // UDP length exceeds packet bounds
	}

	// Reset UDP checksum field (offset + 6 is the UDP checksum location)
	p[offset+6] = 0
	p[offset+7] = 0

	// Calculate pseudo-header sum
	sum := p.pseudoHeaderSum(int(udpLen))

	// Add UDP header and payload
	for i := 0; i < udpLen-1; i += 2 {
		sum += uint32(p[offset+i]) << 8
		sum += uint32(p[offset+i+1])
	}

	if udpLen%2 == 1 {
		sum += uint32(p[offset+udpLen-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	checksum := ^uint16(sum)
	// Special case: UDP checksum 0 is replaced with all ones
	if checksum == 0 {
		checksum = 0xffff
	}
	p[offset+6] = byte(checksum >> 8)
	p[offset+7] = byte(checksum)
}

func (p IPv4Packet) updateICMPChecksum() {
	offset := p.PayloadOffset()
	icmpLen := p.TotalLength() - offset

	// Reset ICMP checksum field
	p[offset+2] = 0
	p[offset+3] = 0

	var sum uint32
	for i := 0; i < icmpLen-1; i += 2 {
		sum += uint32(p[offset+i]) << 8
		sum += uint32(p[offset+i+1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	checksum := ^uint16(sum)
	p[offset+2] = byte(checksum >> 8)
	p[offset+3] = byte(checksum)
}

func (p IPv4Packet) pseudoHeaderSum(transportLen int) uint32 {
	var sum uint32

	// Source IP (4 bytes)
	sum += uint32(p[12]) << 8
	sum += uint32(p[13])
	sum += uint32(p[14]) << 8
	sum += uint32(p[15])

	// Destination IP (4 bytes)
	sum += uint32(p[16]) << 8
	sum += uint32(p[17])
	sum += uint32(p[18]) << 8
	sum += uint32(p[19])

	// Protocol and Length
	sum += uint32(p[9])         // Protocol
	sum += uint32(transportLen) // TCP/UDP length

	return sum
}
