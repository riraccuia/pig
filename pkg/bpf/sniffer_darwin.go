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

package bpf

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ethHeaderLen = 14
)

const (
	BIOCGDIRECTION = 0x40044276
)

// BPFDirection represents the direction of the BPF filter.
type BPFDirection int

const (
	BPF_D_IN    BPFDirection = iota // only capture incoming packets
	BPF_D_INOUT                     // capture incoming and outgoing packets
)

// IcmpEchoRequestFilter is the BPF filter for ICMP echo requests.
var IcmpEchoRequestFilter = []unix.BpfInsn{
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x0000000c}, // ldh [12] - Load halfword (16-bit) from offset 12 (Ethernet type field)
	{Code: 0x15, Jt: 0, Jf: 8, K: 0x00000800}, // jeq #0x800,8,0 - If equal to 0x800 (IPv4), jump 8 instructions forward, else jump 0 (reject)
	{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000017}, // ldb [23] - Load byte from offset 23 (IP protocol field: 14 bytes Ethernet + 9 bytes IP header)
	{Code: 0x15, Jt: 0, Jf: 6, K: 0x00000001}, // jeq #0x1,6,0 - If equal to 1 (ICMP), jump 6 instructions forward, else jump 0 (reject)
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x00000014}, // ldh [20] - Load halfword from offset 20 (ICMP type field: 14 bytes Ethernet + 20 bytes IP + 0 bytes ICMP)
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x00001fff}, // jset #0x1fff,4,0 - If any bits in 0x1fff are set, jump 4 instructions forward, else continue
	{Code: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e}, // ldxb [14] - Load byte from offset 14 with X register (load IP header length)
	{Code: 0x50, Jt: 0, Jf: 0, K: 0x0000000e}, // ldb [14] - Load byte from offset 14 (IP version and header length)
	{Code: 0x15, Jt: 0, Jf: 1, K: 0x00000008}, // jeq #0x8,1,0 - If equal to 8 (ICMP Echo Request), jump 1 instruction forward, else jump 0 (reject)
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00040000},  // ret #262144 - Accept packet (return capture length)
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00000000},  // ret #0 - Reject packet (return 0)
}

// IcmpEchoReplyFilter is the BPF filter for ICMP echo replies.
var IcmpEchoReplyFilter = []unix.BpfInsn{
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x0000000c}, // ldh [12] - Load halfword (16-bit) from offset 12 (Ethernet type field)
	{Code: 0x15, Jt: 0, Jf: 8, K: 0x00000800}, // jeq #0x800,8,0 - If equal to 0x800 (IPv4), jump 8 instructions forward, else jump 0 (reject)
	{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000017}, // ldb [23] - Load byte from offset 23 (IP protocol field: 14 bytes Ethernet + 9 bytes IP header)
	{Code: 0x15, Jt: 0, Jf: 6, K: 0x00000001}, // jeq #0x1,6,0 - If equal to 1 (ICMP), jump 6 instructions forward, else jump 0 (reject)
	{Code: 0x28, Jt: 0, Jf: 0, K: 0x00000014}, // ldh [20] - Load halfword from offset 20 (ICMP type field: 14 bytes Ethernet + 20 bytes IP + 0 bytes ICMP)
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x00001fff}, // jset #0x1fff,4,0 - If any bits in 0x1fff are set, jump 4 instructions forward, else continue
	{Code: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e}, // ldxb [14] - Load byte from offset 14 with X register (load IP header length)
	{Code: 0x50, Jt: 0, Jf: 0, K: 0x0000000e}, // ldb [14] - Load byte from offset 14 (IP version and header length)
	{Code: 0x15, Jt: 0, Jf: 1, K: 0x00000000}, // jeq #0x0,1,0 - If equal to 0 (ICMP Echo Reply), jump 1 instruction forward, else jump 0 (reject)
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00040000},  // ret #262144 - Accept packet (return capture length)
	{Code: 0x6, Jt: 0, Jf: 0, K: 0x00000000},  // ret #0 - Reject packet (return 0)
}

// BPFSniffer represents a BPF packet sniffer.
type BPFSniffer struct {
	bpf    *os.File
	ifName string
	buf    []byte
	filter []unix.BpfInsn // Use unix.BpfInsn instead of custom struct

	// Packet queue for io.ReadCloser implementation
	packetQueue [][]byte
	queueMutex  sync.Mutex
	queueCond   *sync.Cond

	// Background goroutine management
	stopChan chan struct{}
	wg       sync.WaitGroup
	bufPool  sync.Pool
}

// NewBPFSniffer creates a new BPF sniffer instance that takes a BPF filter and the direction of the traffic to capture.
func NewBPFSniffer(ifName string, filter []unix.BpfInsn, direction BPFDirection) (*BPFSniffer, error) {
	// open the BPF device and get a file descriptor
	bpf, err := openBPF()
	if err != nil {
		return nil, fmt.Errorf("failed to open BPF: %w", err)
	}
	// create the sniffer instance
	sniffer := &BPFSniffer{
		bpf:      bpf,
		ifName:   ifName,
		filter:   filter, // Store the filter
		stopChan: make(chan struct{}),
	}
	// Initialize condition variable
	sniffer.queueCond = sync.NewCond(&sniffer.queueMutex)
	// configure the sniffer (e.g apply the filter and set the direction)
	if err := sniffer.configure(direction); err != nil {
		bpf.Close()
		return nil, fmt.Errorf("failed to configure BPF: %w", err)
	}
	// create a buffer pool for the packet buffers
	sniffer.bufPool = sync.Pool{New: func() any {
		b := make([]byte, len(sniffer.buf))
		return &b
	}}
	// Start background packet capture
	sniffer.wg.Add(1)
	go sniffer.capturePackets()
	return sniffer, nil
}

// Read receives a packet from the BPF device.
func (s *BPFSniffer) Read(p []byte) (n int, err error) {
	s.queueMutex.Lock()
	defer s.queueMutex.Unlock()

	// Wait for a packet to be available
	for len(s.packetQueue) == 0 {
		select {
		case <-s.stopChan:
			return 0, io.EOF
		default:
			s.queueCond.Wait()
		}
	}
	// Get the first packet from the queue
	packet := s.packetQueue[0]
	s.packetQueue = s.packetQueue[1:]
	// determine the length of the packet from the ip header
	packetLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if packetLen > len(p) {
		s.putBuffer(packet)
		return 0, fmt.Errorf("buffer too small for packet: need %d, have %d", packetLen, len(p))
	}
	copy(p, packet[:packetLen])
	// free the memory
	s.putBuffer(packet)
	return packetLen, nil
}

// Close implements io.Closer interface.
func (s *BPFSniffer) Close() error {
	// Signal background goroutine to stop
	close(s.stopChan)
	// Wait for background goroutine to finish
	s.wg.Wait()
	if s.bpf == nil {
		return nil
	}
	// Close the BPF device
	return s.bpf.Close()
}

// capturePackets runs in the background to continuously capture packets.
func (s *BPFSniffer) capturePackets() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopChan:
			return
		default:
			if err := s.readAndProcessPackets(); err != nil {
				log.Printf("Packet capture error: %v", err)
				return
			}
		}
	}
}

// readAndProcessPackets reads packets from BPF and adds them to the queue.
func (s *BPFSniffer) readAndProcessPackets() error {
	n, err := s.bpf.Read(s.buf)
	if err != nil {
		return fmt.Errorf("bpf read: %w", err)
	}

	offset := 0

	s.queueMutex.Lock()
	defer s.queueMutex.Unlock()

	foundPackets := 0

	for offset < n {
		// Check if we have enough bytes for a BPF header
		hdrLen := 18 // BPF header is 18 bytes on macOS
		if offset+hdrLen > n {
			break
		}
		// Parse BPF header manually
		// BPF header structure on macOS:
		// - Bytes 0-7: timestamp (8 bytes)
		// - Bytes 8-11: caplen (4 bytes) - captured packet length
		// - Bytes 12-15: datalen (4 bytes) - original packet length
		// - Bytes 16-17: hdrlen (2 bytes) - header length
		// - Bytes 18-19: padding (2 bytes)
		caplen := int(binary.LittleEndian.Uint32(s.buf[offset+8 : offset+12]))  // Captured packet length
		hdrlen := int(binary.LittleEndian.Uint16(s.buf[offset+16 : offset+18])) // Header length
		// Calculate total record length (header + captured data)
		totalLen := hdrlen + caplen
		//fmt.Printf("offset=%d, totalLen=%d, caplen=%d, hdrlen=%d\n", offset, totalLen, caplen, hdrlen)
		// Validate packet record bounds
		if totalLen < hdrLen || offset+totalLen > n {
			break
		}
		// Calculate packet data boundaries (skip BPF header)
		pktStart := offset + hdrlen
		pktEnd := pktStart + caplen
		// skip if the packet is too large
		if pktEnd > n {
			break
		}
		// Skip if no data was captured
		if caplen == 0 {
			offset += totalLen
			// Align to 4-byte boundary: BPF packets are aligned on macOS
			// (offset + 3) & ^3 rounds up to next 4-byte boundary
			// ^3 creates mask 11111100 (clears lowest 2 bits)
			offset = (offset + 3) & ^3
			continue
		}
		// Skip if packet is too small to have ethernet header
		if caplen <= ethHeaderLen {
			offset += totalLen
			// Align to 4-byte boundary
			offset = (offset + 3) & ^3
			continue
		}
		foundPackets++
		// Get buffer from pool and copy packet data
		packetBuf := s.getBuffer()
		packetData := s.buf[pktStart:pktEnd]
		// Copy packet data without ethernet header (strip first 14 bytes)
		copy(packetBuf, packetData[ethHeaderLen:])
		// Add to queue for consumption by Read() method
		s.packetQueue = append(s.packetQueue, packetBuf)
		// Advance to next packet and align to 4-byte boundary
		offset += totalLen
		// Align to 4-byte boundary: ensures we find next BPF header correctly
		offset = (offset + 3) & ^3
	}
	// Signal that packets are available for consumption
	s.queueCond.Signal()
	return nil
}

// openBPF finds and opens an available BPF device.
func openBPF() (*os.File, error) {
	for i := 0; i < 255; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		f, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err == nil {
			return f, nil
		}
		if !os.IsPermission(err) && !os.IsNotExist(err) {
			//return nil, err
		}
	}
	return nil, fmt.Errorf("no /dev/bpf devices available")
}

// configure sets up the BPF device with proper settings.
func (s *BPFSniffer) configure(direction BPFDirection) error {
	if err := s.setImmediateMode(); err != nil {
		return err
	}
	if err := s.bindToInterface(); err != nil {
		return err
	}
	if err := s.setBpfDirection(int(s.bpf.Fd()), int(direction)); err != nil {
		return err
	}
	if err := s.setFilter(); err != nil {
		return err
	}
	bufLen, err := s.getBpfBufLen(int(s.bpf.Fd()))
	if err != nil {
		return err
	}
	s.buf = make([]byte, bufLen)
	return nil
}

func (s *BPFSniffer) getBpfBufLen(fd int) (int, error) {
	return unix.IoctlGetInt(fd, unix.BIOCGBLEN)
}

func (s *BPFSniffer) setBpfDirection(fd int, direction int) error {
	err := unix.IoctlSetPointerInt(fd, BIOCGDIRECTION, direction)
	if err != nil {
		return fmt.Errorf("BIOCGDIRECTION: %v", err)
	}
	return nil
}

// setImmediateMode enables immediate packet delivery.
func (s *BPFSniffer) setImmediateMode() error {
	one := 1
	err := unix.IoctlSetPointerInt(int(s.bpf.Fd()), unix.BIOCIMMEDIATE, one)
	if err != nil {
		return fmt.Errorf("BIOCIMMEDIATE: %v", err)
	}
	return nil
}

// bindToInterface attaches the BPF device to the specified interface.
func (s *BPFSniffer) bindToInterface() error {
	var ifr [16]byte
	copy(ifr[:], s.ifName)
	err := ioctlPtr(int(s.bpf.Fd()), unix.BIOCSETIF, unsafe.Pointer(&ifr[0]))
	if err != nil {
		return fmt.Errorf("BIOCSETIF: %v", err)
	}
	return nil
}

// setFilter configures the BPF filter using the stored filter.
func (s *BPFSniffer) setFilter() error {
	bpfProg := unix.BpfProgram{
		Len:   uint32(len(s.filter)),
		Insns: &s.filter[0],
	}
	err := ioctlPtr(int(s.bpf.Fd()), unix.BIOCSETF, unsafe.Pointer(&bpfProg))
	if err != nil {
		return fmt.Errorf("BIOCSETF: %v", err)
	}
	return nil
}

func ioctlPtr(fd, arg int, ptr unsafe.Pointer) error {
	//nolint:staticcheck
	_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), uintptr(arg), uintptr(ptr))
	if errno != 0 {
		return fmt.Errorf("error: %d", errno)
	}
	return nil
}

func (s *BPFSniffer) getBuffer() []byte {
	return *s.bufPool.Get().(*[]byte)
}

func (s *BPFSniffer) putBuffer(p []byte) {
	s.bufPool.Put(&p)
}
