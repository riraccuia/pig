package adapter

import (
	"net"

	"github.com/riraccuia/pig/pkg/interfaces"
	"github.com/songgao/water"
)

func NewAdapter(config AdapterConfig) (interfaces.TunnelAdapter, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	cfg.Name = "tun0"

	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}

	ip, _, err := net.ParseCIDR(config.Address)
	if err != nil {
		iface.Close()
		return nil, err
	}

	adapter := &TUNAdapter{
		iface:  iface,
		ip:     ip,
		ifName: iface.Name(),
	}

	if err := configureTUN(adapter.ifName, config); err != nil {
		adapter.Close()
		return nil, err
	}

	return adapter, nil
}
