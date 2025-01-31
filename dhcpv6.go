package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/insomniacslk/dhcp/iana"
)

const (
	// The valid lifetime for the IPv6 prefix in the option, expressed in units
	// of seconds.  A value of 0xFFFFFFFF represents infinity.
	dhcpv6DefaultValidLifetime = 60 * time.Second

	// T1 is the duration after which the DHCPv6 client attempts to extended the
	// lease time of an assigned address by contacting the current DHCPv6 and T2
	// is the time after which any DHCPv6 server is contacted. Both values are
	// fractions of the currently configured lease lifetime.
	dhcpv6T1Ratio = 0.75
	dhcpv6T2Ratio = 0.85

	enterpriseNumberMicrosoft = 311
)

// dhcpv6LinkLocalPrefix is the 64-bit link local IPv6 prefix.
var dhcpv6LinkLocalPrefix = []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}

// DHCPv6Handler holds the state for of the DHCPv6 handler method Handler().
type DHCPv6Handler struct {
	logger   *Logger
	serverID dhcpv6.DUID
	config   Config
}

// NewDHCPv6Handler returns a DHCPv6Handler.
func NewDHCPv6Handler(config Config, logger *Logger) *DHCPv6Handler {
	return &DHCPv6Handler{
		logger: logger,
		config: config,
		serverID: &dhcpv6.DUIDLL{
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: config.Interface.HardwareAddr,
		},
	}
}

// Handler implements a server6.Handler.
func (h *DHCPv6Handler) Handler(ctx context.Context) func(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	return func(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
		err := h.handler(conn, peer, m)
		if err != nil && !(errors.Is(err, net.ErrClosed) && ctx.Err() != nil) {
			h.logger.Errorf(err.Error())
		}
	}
}

func (h *DHCPv6Handler) handler(conn net.PacketConn, peerAddr net.Addr, m dhcpv6.DHCPv6) error {
	answer, err := h.createResponse(peerAddr, m)
	if errors.Is(err, errNoResponse) {
		return nil
	} else if err != nil {
		return err
	}

	_, err = conn.WriteTo(answer.ToBytes(), peerAddr)
	if err != nil {
		return fmt.Errorf("write to %s: %w", peerAddr, err)
	}

	return nil
}

var errNoResponse = fmt.Errorf("no response")

func (h *DHCPv6Handler) createResponse(peerAddr net.Addr, m dhcpv6.DHCPv6) (*dhcpv6.Message, error) {
	msg, err := m.GetInnerMessage()
	if err != nil {
		return nil, fmt.Errorf("get inner message: %w", err)
	}

	peer := newPeerInfo(peerAddr, msg)

	shouldRespond, reason := shouldRespondToDHCP(h.config, peer)
	if !shouldRespond {
		h.logger.IgnoreDHCP(m.Type().String(), peer, reason)

		return nil, errNoResponse
	}

	var answer *dhcpv6.Message

	switch m.Type() {
	case dhcpv6.MessageTypeSolicit:
		answer, err = h.handleSolicit(msg, peer)
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRenew:
		answer, err = h.handleRequestRebindRenew(msg, peer)
	case dhcpv6.MessageTypeConfirm:
		answer, err = h.handleConfirm(msg, peer)
	case dhcpv6.MessageTypeRelease:
		answer, err = h.handleRelease(msg, peer)
	case dhcpv6.MessageTypeInformationRequest:
		answer, err = h.handleInformationRequest(msg, peer)
	default:
		h.logger.Debugf("unhandled DHCP message from %s:\n%s", peer, msg.Summary())

		return nil, errNoResponse
	}

	if err != nil {
		return nil, fmt.Errorf("configure response to %T from %s: %w", msg.Type(), peer, err)
	}

	if answer == nil {
		return nil, fmt.Errorf("answer to %T from %s was not configured", msg.Type(), peer)
	}

	return answer, nil
}

func (h *DHCPv6Handler) handleSolicit(msg *dhcpv6.Message, peer peerInfo) (*dhcpv6.Message, error) {
	iaNA, err := extractIANA(msg)
	if err != nil {
		return nil, fmt.Errorf("extract IANA: %w", err)
	}

	ip, opts, err := h.configureResponseOpts(iaNA, msg, peer)
	if err != nil {
		return nil, fmt.Errorf("configure response options: %w", err)
	}

	answer, err := dhcpv6.NewAdvertiseFromSolicit(msg, opts...)
	if err != nil {
		return nil, fmt.Errorf("create ADVERTISE: %w", err)
	}

	h.logger.DHCP(msg.Type(), peer, ip)

	return answer, nil
}

func (h *DHCPv6Handler) handleRequestRebindRenew(msg *dhcpv6.Message, peer peerInfo) (*dhcpv6.Message, error) {
	iaNA, err := extractIANA(msg)
	if err != nil {
		return nil, fmt.Errorf("extract IANA: %w", err)
	}

	ip, opts, err := h.configureResponseOpts(iaNA, msg, peer)
	if err != nil {
		return nil, fmt.Errorf("configure response options: %w", err)
	}

	answer, err := dhcpv6.NewReplyFromMessage(msg, opts...)
	if err != nil {
		return nil, fmt.Errorf("create %s REPLY: %w", msg.Type(), err)
	}

	h.logger.DHCP(msg.Type(), peer, ip)

	return answer, nil
}

func (h *DHCPv6Handler) handleInformationRequest(msg *dhcpv6.Message, peer peerInfo) (*dhcpv6.Message, error) {
	answer, err := dhcpv6.NewReplyFromMessage(msg,
		dhcpv6.WithServerID(h.serverID),
		dhcpv6.WithDNS(h.config.LocalIPv6),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s REPLY: %w", msg.Type(), err)
	}

	h.logger.DHCP(msg.Type(), peer, nil)

	return answer, nil
}

func (h *DHCPv6Handler) handleConfirm(msg *dhcpv6.Message, peer peerInfo) (*dhcpv6.Message, error) {
	answer, err := dhcpv6.NewReplyFromMessage(msg,
		dhcpv6.WithServerID(h.serverID),
		dhcpv6.WithDNS(h.config.LocalIPv6),
		dhcpv6.WithOption(&dhcpv6.OptStatusCode{
			StatusCode:    iana.StatusNotOnLink,
			StatusMessage: iana.StatusNotOnLink.String(),
		}))
	if err != nil {
		return nil, fmt.Errorf("create REPLY: %w", err)
	}

	h.logger.Debugf("rejecting %s from %s", msg.Type().String(), peer)

	return answer, nil
}

func (h *DHCPv6Handler) handleRelease(msg *dhcpv6.Message, peer peerInfo) (*dhcpv6.Message, error) {
	iaNAs, err := extractIANAs(msg)
	if err != nil {
		return nil, err
	}

	opts := []dhcpv6.Modifier{
		dhcpv6.WithOption(&dhcpv6.OptStatusCode{
			StatusCode:    iana.StatusSuccess,
			StatusMessage: iana.StatusSuccess.String(),
		}),
		dhcpv6.WithServerID(h.serverID),
	}

	// send status NoBinding for each address
	for _, iaNA := range iaNAs {
		opts = append(opts, dhcpv6.WithOption(&dhcpv6.OptIANA{
			IaId: iaNA.IaId,
			Options: dhcpv6.IdentityOptions{
				Options: []dhcpv6.Option{
					&dhcpv6.OptStatusCode{
						StatusCode:    iana.StatusNoBinding,
						StatusMessage: iana.StatusNoBinding.String(),
					},
				},
			},
		}))
	}

	answer, err := dhcpv6.NewReplyFromMessage(msg, opts...)
	if err != nil {
		return nil, fmt.Errorf("create REPLY: %w", err)
	}

	h.logger.Debugf("aggreeing to RELEASE from %s", peer)

	return answer, nil
}

// configureResponseOpts returns the IP that should be assigned based on the
// request IA_NA and the modifiers to configure the response with that IP and
// the DNS server configured in the DHCPv6Handler.
func (h *DHCPv6Handler) configureResponseOpts(requestIANA *dhcpv6.OptIANA,
	msg *dhcpv6.Message, peer peerInfo,
) (net.IP, []dhcpv6.Modifier, error) {
	cid := msg.GetOneOption(dhcpv6.OptionClientID)
	if cid == nil {
		return nil, nil, fmt.Errorf("no client ID option from DHCPv6 message")
	}

	duid, err := dhcpv6.DUIDFromBytes(cid.ToBytes())
	if err != nil {
		return nil, nil, fmt.Errorf("deserialize DUID: %w", err)
	}

	var clientMAC net.HardwareAddr

	switch d := duid.(type) {
	case *dhcpv6.DUIDLL:
		clientMAC = d.LinkLayerAddr
	case *dhcpv6.DUIDLLT:
		clientMAC = d.LinkLayerAddr
	}

	var leasedIP net.IP

	if clientMAC == nil {
		h.logger.Debugf("DUID does not contain link layer address")

		randomIP, err := generateDeterministicRandomAddress(peer.IP)
		if err != nil {
			h.logger.Debugf("could not generate deterministic address (using SLAAC IP instead): %v", err)

			leasedIP = peer.IP
		} else {
			leasedIP = randomIP
		}
	} else {
		if h.logger != nil {
			go h.logger.HostInfoCache.SaveMACFromIP(peer.IP, clientMAC)
		}

		leasedIP = append(leasedIP, dhcpv6LinkLocalPrefix...)
		leasedIP = append(leasedIP, 0, 0)
		leasedIP = append(leasedIP, clientMAC...)
	}

	// if the IP has the first bit after the prefix set, Windows won't route
	// queries via this IP and use the regular self-generated link-local address
	// instead.
	leasedIP[8] |= 0b10000000

	return leasedIP, []dhcpv6.Modifier{
		dhcpv6.WithServerID(h.serverID),
		dhcpv6.WithDNS(h.config.LocalIPv6),
		dhcpv6.WithOption(&dhcpv6.OptIANA{
			IaId: requestIANA.IaId,
			T1:   time.Duration(dhcpv6T1Ratio * float64(h.config.LeaseLifetime)),
			T2:   time.Duration(dhcpv6T2Ratio * float64(h.config.LeaseLifetime)),
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

func generateDeterministicRandomAddress(peer net.IP) (net.IP, error) {
	if len(peer) != net.IPv6len {
		return nil, fmt.Errorf("invalid length of IPv6 address: %d bytes", len(peer))
	}

	prefixLength := net.IPv6len / 2 //nolint:mnd

	seed := binary.LittleEndian.Uint64(peer[prefixLength:])

	deterministicAddress := make([]byte, prefixLength)

	n, err := rand.New(rand.NewSource(int64(seed))).Read(deterministicAddress) //nolint:gosec
	if err != nil {
		return nil, err
	}

	if n != prefixLength {
		return nil, fmt.Errorf("read %d random bytes instead of %d", n, prefixLength)
	}

	var newIP net.IP
	newIP = append(newIP, dhcpv6LinkLocalPrefix...)
	newIP = append(newIP, deterministicAddress...)

	return newIP, nil
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

func extractIANAs(innerMessage *dhcpv6.Message) ([]*dhcpv6.OptIANA, error) {
	iaNAOpts := innerMessage.GetOption(dhcpv6.OptionIANA)
	if iaNAOpts == nil {
		return nil, fmt.Errorf("message does not contain IANAs:\n%s", innerMessage.Summary())
	}

	iaNAs := make([]*dhcpv6.OptIANA, 0, len(iaNAOpts))

	for i, iaNAOpt := range iaNAOpts {
		iaNA, ok := iaNAOpt.(*dhcpv6.OptIANA)
		if !ok {
			return nil, fmt.Errorf("unexpected type for IANA option %d: %T", i, iaNAOpt)
		}

		iaNAs = append(iaNAs, iaNA)
	}

	return iaNAs, nil
}

// RunDHCPv6Server starts a DHCPv6 server which assigns a DNS server.
func RunDHCPv6Server(ctx context.Context, logger *Logger, config Config) error {
	listenAddr := &net.UDPAddr{
		IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
		Port: dhcpv6.DefaultServerPort,
		Zone: config.Interface.Name,
	}

	dhcvpv6Handler := NewDHCPv6Handler(config, logger)

	conn, err := ListenUDPMulticast(config.Interface, listenAddr)
	if err != nil {
		return err
	}

	server, err := server6.NewServer(config.Interface.Name, nil, dhcvpv6Handler.Handler(ctx),
		server6.WithConn(conn))
	if err != nil {
		return fmt.Errorf("starting DHCPv6 server: %w", err)
	}

	go func() {
		<-ctx.Done()

		_ = server.Close()
	}()

	logger.Infof("listening via UDP on %s", listenAddr)

	err = server.Serve()

	// if the server is stopped via ctx, we suppress the resulting errors that
	// result from server.Close closing the connection.
	if ctx.Err() != nil {
		return nil //nolint:nilerr
	}

	return err
}

type peerInfo struct {
	IP               net.IP
	Hostnames        []string
	EnterpriseNumber uint32
}

func newPeerInfo(addr net.Addr, innerMessage *dhcpv6.Message) peerInfo {
	p := peerInfo{
		IP: addrToIP(addr),
	}

	en, err := enterpriseNumber(innerMessage)
	if err == nil {
		p.EnterpriseNumber = en
	}

	fqdnOpt := innerMessage.GetOneOption(dhcpv6.OptionFQDN)
	if fqdnOpt == nil {
		return p
	}

	fqdn, ok := fqdnOpt.(*dhcpv6.OptFQDN)
	if !ok {
		return p
	}

	p.Hostnames = make([]string, 0, len(fqdn.DomainName.Labels))

	for _, label := range fqdn.DomainName.Labels {
		p.Hostnames = append(p.Hostnames, strings.TrimRight(label, "."))
	}

	return p
}

func enterpriseNumber(msg *dhcpv6.Message) (uint32, error) {
	vcOption := msg.GetOneOption(dhcpv6.OptionVendorClass)
	if vcOption != nil {
		vendorClass, ok := vcOption.(*dhcpv6.OptVendorClass)
		if ok {
			return vendorClass.EnterpriseNumber, nil
		}
	}

	cids := msg.GetOption(dhcpv6.OptionClientID)
	if len(cids) == 0 {
		return 0, fmt.Errorf("no client ID option from DHCPv6 message")
	}

	for _, cid := range cids {
		duid, err := dhcpv6.DUIDFromBytes(cid.ToBytes())
		if err != nil {
			return 0, fmt.Errorf("deserialize DUID: %w", err)
		}

		duiden, ok := duid.(*dhcpv6.DUIDEN)
		if !ok {
			continue
		}

		return duiden.EnterpriseNumber, nil
	}

	return 0, fmt.Errorf("no enterprise DUID present")
}

// String returns the string representation of a peerInfo.
func (p peerInfo) String() string {
	if len(p.Hostnames) > 0 {
		return p.IP.String() + " (" + strings.Join(p.Hostnames, ", ") + ")"
	}

	return p.IP.String()
}

func addrToIP(addr net.Addr) net.IP {
	udpAddr, ok := addr.(*net.UDPAddr)
	if ok {
		return udpAddr.IP
	}

	addrString := addr.String()

	for strings.Contains(addrString, "/") || strings.Contains(addrString, "%") {
		addrString = strings.SplitN(addrString, "/", 2)[0] //nolint:mnd
		addrString = strings.SplitN(addrString, "%", 2)[0] //nolint:mnd
	}

	splitAddr, _, err := net.SplitHostPort(addrString)
	if err == nil {
		addrString = splitAddr
	}

	return net.ParseIP(addrString)
}

func enterpriseNumberStringWithFallback(enterpriseNumber uint32) string {
	ens := enterpriseNumberString(enterpriseNumber)
	if ens == "" {
		return fmt.Sprintf("Enterprise Number %d", enterpriseNumber)
	}

	return ens
}

// https://www.iana.org/assignments/enterprise-numbers/
func enterpriseNumberString(enterpriseNumber uint32) string {
	//nolint:mnd
	switch enterpriseNumber {
	case 2:
		return "IBM"
	case 4:
		return "Unix"
	case 9:
		return "Cisco"
	case 11:
		return "Hewlett-Packard"
	case 23:
		return "Novell"
	case 42:
		return "Sun Microsystems"
	case 63:
		return "Apple"
	case 64:
		return "AT&T"
	case 77:
		return "LAN Manager"
	case 79, 189, 211:
		return "Fujitsu"
	case 94:
		return "Nokia"
	case 109:
		return "Broadcom"
	case 111:
		return "Oracle"
	case enterpriseNumberMicrosoft:
		return "Microsoft"
	case 152:
		return "Solarix"
	case 153:
		return "Unifi"
	case 161:
		return "Motorola"
	case 171:
		return "D-Link"
	case 179:
		return "Schneider & Koch & Co"
	case 236:
		return "Samsung"
	case 253:
		return "Xerox"
	case 1347, 29714:
		return "KYOCERA"
	case 2435:
		return "Brother"
	case 641:
		return "Lexmark"
	case 1065, 1602:
		return "Canon"
	default:
		return ""
	}
}
