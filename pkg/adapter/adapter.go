package adapter

import (
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

type AdapterConfig struct {
	Address string
	MTU     int
}

func NewAdapter(cfg *config.Config) (common.TunnelAdapter, error) {
	adapterCfg := AdapterConfig{
		Address: cfg.TunnelAddress,
		MTU:     cfg.MTU,
	}
	return newAdapter(adapterCfg)
}
