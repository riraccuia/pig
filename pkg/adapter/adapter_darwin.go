package adapter

import (
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/songgao/water"
)

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	// First get the interface name and configure it
	ifName, utun, err := configureTUN(config)
	if err != nil {
		return nil, err
	}

	// Create the TUN device
	cfg := water.Config{
		DeviceType: water.TUN,
	}

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
		iface:  utun,
		ip:     ip,
		ifName: ifName,
	}

	return adapter, nil
}
