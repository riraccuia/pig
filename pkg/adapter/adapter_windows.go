package adapter

import (
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
)

const tunName = "pig"

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	//wintun.SetLogger(nil)

	adapter, err := CreateTUNWithRequestedGUID(tunName, WintunStaticRequestedGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to create wintun adapter: %v", err)
	}

	ip, _, err := net.ParseCIDR(config.Address)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to parse IP: %v", err)
	}

	adapter.ip = ip

	if err := configureWinTun(tunName, config); err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to configure adapter: %v", err)
	}

	return adapter, nil
}
