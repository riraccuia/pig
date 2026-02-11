package network

import (
	"golang.org/x/sys/windows"
)

// setSockoptIPV6DontFrag sets the IPV6_DONTFRAG socket option.
// https://www.ietf.org/archive/id/draft-seemann-tsvwg-udp-fragmentation-02.txt
func setSockoptIPV6DontFrag(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 0x3e, 1) // 0x3e is IPV6_DONTFRAG
}

func setSockoptReuseAddr(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}
