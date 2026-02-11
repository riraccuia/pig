package network

func (p IPv6Packet) UpdateChecksum() {
	protocol, offset, transportLen, ok := p.transportHeader()
	if !ok {
		return
	}

	switch protocol {
	case ipProtoTCP:
		p.updateTCPChecksum()
	case ipProtoUDP:
		p.updateUDPChecksum()
	case ipProtoICMPv6:
		p.updateICMPv6Checksum(offset, transportLen)
	}
}

func (p IPv6Packet) updateTCPChecksum() {
	protocol, offset, tcpLen, ok := p.transportHeader()
	if !ok || protocol != ipProtoTCP {
		return
	}

	if len(p) < offset+20 {
		return
	}

	// Reset TCP checksum field (offset + 16 is the TCP checksum location)
	p[offset+16] = 0
	p[offset+17] = 0

	// Calculate pseudo-header sum
	sum := p.pseudoHeaderSum(ipProtoTCP, tcpLen)

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

func (p IPv6Packet) updateUDPChecksum() {
	protocol, offset, transportLen, ok := p.transportHeader()
	if !ok || protocol != ipProtoUDP {
		return
	}

	// Validate we have enough space for UDP header (8 bytes)
	if len(p) < offset+8 {
		return
	}

	// Get UDP length and validate it (0 is allowed for IPv6 jumbograms).
	udpLen := int(uint16(p[offset+4])<<8 | uint16(p[offset+5]))
	if udpLen == 0 {
		udpLen = transportLen
	}
	if udpLen < 8 || offset+udpLen > len(p) {
		return
	}

	// Reset UDP checksum field (offset + 6 is the UDP checksum location)
	p[offset+6] = 0
	p[offset+7] = 0

	// Calculate pseudo-header sum
	sum := p.pseudoHeaderSum(ipProtoUDP, udpLen)

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

func (p IPv6Packet) updateICMPv6Checksum(offset, icmpLen int) {
	if len(p) < offset+4 || offset+icmpLen > len(p) || icmpLen < 4 {
		return
	}

	// Reset ICMPv6 checksum field
	p[offset+2] = 0
	p[offset+3] = 0

	// ICMPv6 checksum includes IPv6 pseudo-header.
	sum := p.pseudoHeaderSum(ipProtoICMPv6, icmpLen)
	for i := 0; i < icmpLen-1; i += 2 {
		sum += uint32(p[offset+i]) << 8
		sum += uint32(p[offset+i+1])
	}

	if icmpLen%2 == 1 {
		sum += uint32(p[offset+icmpLen-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	checksum := ^uint16(sum)
	p[offset+2] = byte(checksum >> 8)
	p[offset+3] = byte(checksum)
}

func (p IPv6Packet) pseudoHeaderSum(nextHeader uint8, upperLayerLen int) uint32 {
	var sum uint32

	// Source IP (16 bytes)
	for i := 8; i < 24; i += 2 {
		sum += uint32(p[i]) << 8
		sum += uint32(p[i+1])
	}

	// Destination IP (16 bytes)
	for i := 24; i < 40; i += 2 {
		sum += uint32(p[i]) << 8
		sum += uint32(p[i+1])
	}

	// Upper-layer packet length (32-bit value)
	sum += uint32(uint16(uint32(upperLayerLen) >> 16))
	sum += uint32(uint16(upperLayerLen))

	// Next Header
	sum += uint32(nextHeader)

	return sum
}
