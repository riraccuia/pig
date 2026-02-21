package controller

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/route"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/transport"
)

func (c *Controller) StartClient() {
	c.Add(1)
	go c.startClient(c.ctx, c.cfg)
}

func (c *Controller) startClient(ctx context.Context, cfg *config.Config) {
	defer c.Done()

	c.scriptExecutor = script.New(c.logger, cfg.StartScript, cfg.StopScript)

	var (
		tunnel        *client.Client
		dialer        func() (transport.Conn, error)
		authenticator common.Authenticator
		err           error
	)

	transportStr := "|"
	if !cfg.TunnelConfig.ICE.Enabled {
		transportStr = fmt.Sprintf("| Transport:%s |", cfg.TunnelConfig.Proto)
	}

	c.logger.Infof("Starting pig | Mode: %s %s MTU: %d", cfg.Mode, transportStr, cfg.TunnelConfig.MTU)

	switch cfg.TunnelConfig.ICE.Enabled {
	case true:
		c.logger.Info("ICE enabled | STUN server: ", cfg.TunnelConfig.ICE.STUNAddress, " | MQTT broker: ", cfg.TunnelConfig.ICE.Signaling.MQTTBrokerAddress)
	case false:
		c.logger.Infof("Target: %s:%d, proto: %s", cfg.TunnelConfig.Target.Address, cfg.TunnelConfig.Target.Port, cfg.TunnelConfig.Proto)
	}

	// Create authenticator if configured
	authenticator, err = c.createClientAuthenticator(cfg.TunnelConfig.Auth)
	if err != nil {
		c.logger.Fatalf("Failed to create authenticator: %v", err)
	}
	dialer, err = c.getDialFunc(ctx, &cfg.TunnelConfig)
	if err != nil {
		c.logger.Fatalf("Failed to get client dialer: %v", err)
	}
	tunnel, err = client.New(c.logger, &cfg.TunnelConfig, authenticator)
	if err != nil {
		c.logger.Fatalf("Failed to create client: %v", err)
	}

	c.HandleClientEvents(tunnel)

	t := time.NewTimer(time.Millisecond)
	for {
		select {
		case <-t.C:
			// continue with the loop
		case <-ctx.Done():
			c.logger.Debugf("Controller exiting, client tunnel stopped")
			return
		}
		if err := tunnel.Start(ctx, dialer); err != nil {
			c.logger.Fatalf("Failed to start tunnel: %v", err)
		}
		tunnel.WaitClose()
		t.Reset(time.Second)
	}
}

func (c *Controller) HandleClientEvents(tunnel *client.Client) {
	c.Add(1)
	go c.handleClientEvents(c.ctx, c.cfg, tunnel)
	runtime.Gosched()
}

func (c *Controller) handleClientEvents(ctx context.Context, cfg *config.Config, tunnel *client.Client) {
	defer c.Done()
	for {
		var event *client.EventContext
		select {
		case event = <-tunnel.Events():
		case <-ctx.Done():
			tunnel.WaitClose()
			// if the tunnel is closed, and there are no more events, exit the loop
			if len(tunnel.Events()) == 0 {
				c.logger.Debugf("Stopped monitoring client events")
				return
			}
			continue
		}
		c.logger.Debugf("Client event received: %s", event.Event)
		c.setupClientRoutes(&cfg.RouteConfig, tunnel.GetAdapter(), event)
		c.executeClientScript(cfg.TunnelConfig.Proto, tunnel.GetAdapter(), event)
	}
}

func (c *Controller) setupClientRoutes(cfg *config.RouteConfig, adapter common.TunnelAdapter, event *client.EventContext) {
	if !cfg.Enabled {
		return
	}
	if event.Event != client.EventConnected {
		c.logger.Infof("Cleaning up routes")
		err := c.routeManager.Cleanup()
		if err != nil {
			c.logger.Errorf("Failed to cleanup routes: %v", err)
		}
		return
	}
	// get the remote address from the event context conn
	remoteAddr := event.Conn.RemoteAddr()
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil && remoteAddr.Network() == "ip" {
		// there is no port for IP addresses
		host = remoteAddr.String()
		err = nil
	}
	if err != nil {
		c.logger.Errorf("Failed to split host and port (%s): %v", remoteAddr.Network(), err)
		return
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		c.logger.Errorf("Failed to parse IP: %v", err)
		return
	}
	remoteMaskBits := 32
	if remoteIP.To4() == nil {
		remoteMaskBits = 128
	}
	peerRoute := config.Route{
		Destination: fmt.Sprintf("%s/%d", remoteIP.String(), remoteMaskBits),
		Type:        config.RouteTypeBypass,
	}
	// work with a hard copy of the routes, adding the peer route first
	for _, tRoute := range append([]config.Route{peerRoute}, cfg.Routes...) {
		_, ipNet, err := net.ParseCIDR(tRoute.Destination)
		if err != nil {
			c.logger.Errorf("Failed to parse configuration route (type: %s): %v", tRoute.Type, err)
			continue
		}
		switch tRoute.Type {
		case config.RouteTypeBypass:
			c.logger.Infof("Bypassing %s", ipNet.String())
			err = c.routeManager.AddRouteToBestRoute(ipNet)
		case config.RouteTypeStatic:
			gateway := net.ParseIP(tRoute.Gateway)
			if gateway == nil {
				c.logger.Errorf("Failed to parse gateway: %v", tRoute.Gateway)
				continue
			}
			interfaceName := ""
			if tRoute.Interface != "" {
				interfaceName = tRoute.Interface
			}
			logStr := fmt.Sprintf("Adding static route for %s via %s", ipNet.String(), gateway.String())
			if interfaceName != "" {
				logStr += fmt.Sprintf(" on <%s>", interfaceName)
			}
			c.logger.Infof(logStr)
			err = c.routeManager.AddRoute(&route.Route{
				Destination: ipNet,
				Gateway:     gateway,
				Interface:   interfaceName,
			})
		case config.RouteTypeTunnel:
			c.logger.Infof("Routing %s to %s via %s", ipNet.String(), adapter.IP().String(), adapter.Name())
			err = c.routeManager.AddRoute(&route.Route{
				Destination: ipNet,
				Gateway:     adapter.IP(),
				Interface:   adapter.Name(),
			})
		}
		if err != nil {
			c.logger.Errorf("Failed to add route: %v", err)
		}
	}
}
