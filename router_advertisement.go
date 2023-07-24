package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
)

const (
	raHopLimit              = 0
	raDefaultRouterLifetime = 180 * time.Second
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

	defer func() { _ = conn.Close() }()

	err = conn.JoinGroup(ipv6LinkLocalAllRouters)
	if err != nil {
		return fmt.Errorf("joining multicast group: %w", err)
	}

	var (
		advertizedDNSServer net.IP
		dnsLiftime          = config.RAPeriod
	)

	if !config.NoRADNS {
		advertizedDNSServer = config.RelayIPv6
	}

	time.Sleep(raDelay) // time for DHCPv6 server to start

	for {
		logger.Infof("sending router advertisement%s on %s", raPropertyString(config.RouterLifetime, dnsLiftime), iface.Name)

		err := sendRouterAdvertisement(conn, iface.HardwareAddr, config.RouterLifetime, advertizedDNSServer, dnsLiftime)
		if err != nil {
			return err
		}

		timer := time.NewTimer(config.RAPeriod)

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			logger.Infof("sending router de-advertisement on %s", iface.Name)

			// de-advertise to remove gateway and DNS server from client configuration
			return sendRouterAdvertisement(conn, iface.HardwareAddr, 0, config.RelayIPv6, 0)
		case <-timer.C:
			continue
		}
	}
}

func sendRouterAdvertisement(c *ndp.Conn, routerMAC net.HardwareAddr, routerLifetime time.Duration,
	dnsAddr net.IP, dnsLifetime time.Duration,
) error {
	raMessage := &ndp.RouterAdvertisement{
		CurrentHopLimit:      raHopLimit,
		ManagedConfiguration: true,
		OtherConfiguration:   true,

		RouterSelectionPreference: ndp.High,
		RouterLifetime:            routerLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      routerMAC,
			},
		},
	}

	if dnsAddr != nil && false {
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

	err := c.WriteTo(raMessage, nil, ipv6LinkLocalAllNodes)
	if err != nil {
		return fmt.Errorf("sending router advertisement: %w", err)
	}

	return nil
}

func raPropertyString(routerLifetime time.Duration, dnsLifetime time.Duration) string {
	switch {
	case routerLifetime == 0 && dnsLifetime != 0:
		return " with DNS server"
	case routerLifetime != 0 && dnsLifetime == 0:
		return " with gateway"
	case routerLifetime != 0 && dnsLifetime != 0:
		return " with DNS server and gateway"
	default:
		return ""
	}
}
