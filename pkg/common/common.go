package common

import (
	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/interfaces"
	"github.com/riraccuia/pig/pkg/packet"
)

const (
	QueueSize = 1024
)

type PacketQueue chan packet.IPv4Packet

func NewAdapter(cfg *config.Config) (interfaces.TunnelAdapter, error) {
	adapterCfg := adapter.AdapterConfig{
		Address: cfg.TunnelAddress,
		MTU:     cfg.MTU,
	}
	return adapter.NewAdapter(adapterCfg)
}
