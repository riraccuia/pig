//go:build !windows && !darwin && unix

package network

import "golang.org/x/sys/unix"

// setSockoptIPV6DontFrag sets the IP_PMTUDISC_PROBE socket option.
// https://www.ietf.org/archive/id/draft-seemann-tsvwg-udp-fragmentation-02.txt
func setSockoptIPV6DontFrag(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IP_PMTUDISC_PROBE, 1)
}

func setSockoptReuseAddr(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
}

func setSockoptReusePort(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
