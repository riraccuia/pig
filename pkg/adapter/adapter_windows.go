package adapter

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const tunName = "pig"

type WinTunAdapter struct {
	adapter *wintun.Adapter
	session *wintun.Session
	ip      net.IP
}

func NewAdapter(config AdapterConfig) (TunnelAdapter, error) {
	wintun.SetLogger(nil)

	adapter, err := wintun.CreateAdapter(tunName, "pig", &windows.GUID{
		Data1: 0x0000000,
		Data2: 0x0000,
		Data3: 0x0000,
		Data4: [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create wintun adapter: %v", err)
	}

	session, err := adapter.StartSession(0x800000) // 8MB ring buffer
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to start wintun session: %v", err)
	}

	ip, _, err := net.ParseCIDR(config.Address)
	if err != nil {
		session.End()
		adapter.Close()
		return nil, fmt.Errorf("failed to parse IP: %v", err)
	}

	w := &WinTunAdapter{
		adapter: adapter,
		session: session,
		ip:      ip,
	}

	if err := configureWinTun(adapter.Name(), config); err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to configure adapter: %v", err)
	}

	return w, nil
}

func (w *WinTunAdapter) Read(b []byte) (int, error) {
	packet, err := w.session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	n := copy(b, packet)
	w.session.ReleaseReceivePacket(packet)
	return n, nil
}

func (w *WinTunAdapter) Write(b []byte) (int, error) {
	packet := w.session.AllocateSendPacket(len(b))
	copy(packet, b)
	w.session.SendPacket(packet)
	return len(b), nil
}

func (w *WinTunAdapter) Close() error {
	w.session.End()
	return w.adapter.Close()
}

func (w *WinTunAdapter) IP() net.IP {
	return w.ip
}
