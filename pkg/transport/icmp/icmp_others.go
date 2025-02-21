//go:build !linux

package icmp

func initSystem() error {
	return nil
}
