package demux

import (
	"context"
	"net"
	"testing"

	"github.com/riraccuia/pig/pkg/config"
)

func TestDemuxLookupPrefersSmallerSubnet(t *testing.T) {
	d := New(nil, nil, 1500)
	ctx := context.Background()

	ta1 := d.NewAdapter(ctx, 64)
	ta2 := d.NewAdapter(ctx, 64)
	ta3 := d.NewAdapter(ctx, 64)

	d.AddRoutes(ta1, []config.Route{{Destination: "0.0.0.0/0"}})
	d.AddRoutes(ta2, []config.Route{{Destination: "10.0.0.0/24"}})
	d.AddRoutes(ta3, []config.Route{{Destination: "10.0.0.0/29"}})

	if got := d.routeTable.lookup(net.ParseIP("10.0.0.1")); got != ta3 {
		t.Errorf("lookup(10.0.0.1) = %v, want ta3 (/29 over /24 over /0)", got)
	}
	if got := d.routeTable.lookup(net.ParseIP("10.0.0.254")); got != ta2 {
		t.Errorf("lookup(10.0.0.254) = %v, want ta2 (/24 over /0)", got)
	}
	if got := d.routeTable.lookup(net.ParseIP("192.168.1.1")); got != ta1 {
		t.Errorf("lookup(192.168.1.1) = %v, want ta1", got)
	}
}
