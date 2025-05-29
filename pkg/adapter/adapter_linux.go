package adapter

import (
	"io"
	"net"

	"github.com/riraccuia/pig/pkg/common"
)

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	ifName, utun, err := configureTUN(config)
	if err != nil {
		return nil, err
	}

	ip, _, err := net.ParseCIDR(config.Address)
	if err != nil {
		utun.Close()
		return nil, err
	}

	adapter := &TUNAdapter{
		iface:  utun,
		ip:     ip,
		ifName: ifName,
	}

	return adapter, nil
}

func (a *TUNAdapter) Queues() []io.ReadWriteCloser {
	return a.iface.(*tunAdapter).queues
}
