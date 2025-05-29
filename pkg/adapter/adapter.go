package adapter

import (
	"github.com/riraccuia/pig/pkg/common"
)

type AdapterConfig struct {
	Address string
	MTU     int
	// MultiQueue enables tun multi-queue support
	// It is only supported on Linux
	MultiQueue bool
}

func NewAdapter(cfg AdapterConfig) (common.TunnelAdapter, error) {
	return newAdapter(cfg)
}
