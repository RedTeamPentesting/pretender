package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/ndp"
)

const (
	raHopLimit       = 0
	raPrefixLength   = 64
	raRouterLifetime = 1800 * time.Second
	raDelay          = 500 * time.Millisecond
	raDefaultPeriod  = 3 * time.Minute
)

// SendPeriodicRouterAdvertisements sends periodic router advertisement messages.
func SendPeriodicRouterAdvertisements(ctx context.Context, logger *Logger, config Config) error {
	iface, err := net.InterfaceByName(config.Interface.Name)
	if err != nil {
		return fmt.Errorf("selecting interface %q: %w", config.Interface.Name, err)
	}

	conn, _, err := ndp.Listen(config.Interface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("dialing (%s): %w", config.Interface.Name, err)
	}

	if err := conn.JoinGroup(net.IPv6linklocalallrouters); err != nil {
		return fmt.Errorf("joining multicast group: %w", err)
	}

	defer func() { _ = conn.Close() }()

	time.Sleep(raDelay) // time for DHCPv6 server to start

	for {
		logger.Infof("sending router advertisement on %s", iface.Name)

		err := sendRouterAdvertisement(conn, iface.HardwareAddr)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(config.RAPeriod):
			continue
		}
	}
}

func sendRouterAdvertisement(c *ndp.Conn, routerMAC net.HardwareAddr) error {
	m := &ndp.RouterAdvertisement{
		CurrentHopLimit:      raHopLimit,
		ManagedConfiguration: true,
		OtherConfiguration:   true,

		RouterSelectionPreference: ndp.High,
		RouterLifetime:            raRouterLifetime,
		Options: []ndp.Option{
			&ndp.PrefixInformation{
				PrefixLength:                   raPrefixLength,
				AutonomousAddressConfiguration: true,
				ValidLifetime:                  dhcpv6DefaultValidLifetime,
				PreferredLifetime:              dhcpv6DefaultValidLifetime,
				Prefix:                         net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      routerMAC,
			},
		},
	}

	err := c.WriteTo(m, nil, net.IPv6linklocalallnodes)
	if err != nil {
		return fmt.Errorf("sending router advertisement: %w", err)
	}

	return nil
}
