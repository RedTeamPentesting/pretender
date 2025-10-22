package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	isatapHostname       = "isatap"
	defaultLookupTimeout = 1 * time.Second
)

func shouldRespondToNameResolutionQuery(config *Config, host string, queryType uint16,
	from net.IP, fromHostnames []string, handlerType HandlerType,
) (bool, string) {
	var hostWithService string

	if queryType == dns.TypeSRV {
		hostWithService = host
		host = removeServiceAndPort(host)
	}

	if config.spoofingTemporarilyDisabled {
		return false, "spoofing is temporarily disabled"
	}

	if config.DryMode {
		return false, "dry mode"
	}

	if config.SpoofResponseName != "" && (handlerType == HandlerTypeMDNS || handlerType == HandlerTypeNetBIOS) {
		return false, "response name spoofing not supported for " + string(handlerType)
	}

	if strings.HasPrefix(strings.ToLower(host), isatapHostname) {
		return false, "ISATAP is always ignored"
	}

	if queryType == dns.TypeSOA && config.SOAHostname == "" {
		return false, "no SOA hostname configured"
	}

	if len(config.SpoofFor) > 0 && !containsIP(config.SpoofFor, from) &&
		!containsAnyHostname(config.SpoofFor, fromHostnames...) {
		return false, "host address and name not in spoof-for list"
	}

	if len(config.DontSpoofFor) > 0 {
		if containsIP(config.DontSpoofFor, from) {
			return false, "host address included in dont-spoof-for list"
		}

		if containsAnyHostname(config.DontSpoofFor, fromHostnames...) {
			return false, "hostname included in dont-spoof-for list"
		}
	}

	if len(config.Spoof) > 0 && !containsAnyHostname(config.Spoof, host) {
		return false, "domain not in spoof list"
	}

	if len(config.DontSpoof) > 0 && containsAnyHostname(config.DontSpoof, host) {
		return false, "domain included in dont-spoof list"
	}

	if !config.SpoofTypes.ShouldSpoof(queryType) {
		return false, fmt.Sprintf("type %s is not in spoof-types list", dnsQueryType(queryType))
	}

	if queryType == dns.TypeSRV && !config.SpoofSRV.Contains(hostWithService) {
		service, _, _ := strings.Cut(hostWithService, ".")

		return false, fmt.Sprintf("service %s is not in spoof-srv list", strings.TrimPrefix(service, "_"))
	}

	switch {
	case queryType == dns.TypeA && config.RelayIPv4 == nil:
		return false, "no IPv4 relay address configured"
	case queryType == dns.TypeAAAA && config.RelayIPv6 == nil:
		return false, "no IPv6 relay address configured"
	}

	return true, ""
}

func shouldRespondToDHCP(config *Config, from peerInfo) (bool, string) {
	if config.DryMode && !config.DryWithDHCPv6Mode {
		return false, "dry mode"
	}

	if len(from.Hostnames) == 0 && config.IgnoreDHCPv6NoFQDN {
		return false, "no FQDN in DHCPv6 message"
	}

	if len(config.SpoofFor) > 0 && !containsPeer(config.SpoofFor, from) {
		return false, "host not in spoof-for list"
	}

	if len(config.DontSpoofFor) > 0 && containsPeer(config.DontSpoofFor, from) {
		return false, "host included in dont-spoof-for list"
	}

	if config.IgnoreNonMicrosoftDHCP && from.EnterpriseNumber != enterpriseNumberMicrosoft {
		enterpriseNumberSuffix := ""
		if ens := enterpriseNumberString(from.EnterpriseNumber); ens != "" {
			enterpriseNumberSuffix = " (" + ens + ")"
		}

		return false, fmt.Sprintf("enterprise number %d%s does not belong to Microsoft (%d)",
			from.EnterpriseNumber, enterpriseNumberSuffix, enterpriseNumberMicrosoft)
	}

	return true, ""
}

type hostMatcher struct {
	IPs                      []net.IP
	Hostname                 string
	HostnameRE               *regexp.Regexp
	originalWildcardHostname string
}

var hostMatcherLookupFunction = lookupIPWithTimeout

func newHostMatcher(hostnameOrIP string, resolveIPs bool, dnsTimeout time.Duration) (*hostMatcher, error) {
	ip := net.ParseIP(hostnameOrIP)
	if ip != nil { // hostnameOrIP is an IP
		return &hostMatcher{IPs: []net.IP{ip}}, nil
	}

	if hostnameOrIP == "." {
		return &hostMatcher{Hostname: "."}, nil
	}

	hostnameOrIP = normalizeHostname(hostnameOrIP)
	hasSubdomainWildcard := strings.HasPrefix(hostnameOrIP, ".")
	hasArbitraryWildcard := strings.Contains(hostnameOrIP, "*")

	var resolvedIPs []net.IP

	switch {
	case hasSubdomainWildcard && hasArbitraryWildcard:
		return nil, fmt.Errorf("subdomain wildcard (leading .) and arbitrary wildcard (*) cannot be used together")
	case hasSubdomainWildcard:
		parentDomain := strings.TrimLeft(hostnameOrIP, ".")

		if resolveIPs {
			resolvedIPs, _ = hostMatcherLookupFunction(parentDomain, dnsTimeout)
		}

		return &hostMatcher{IPs: resolvedIPs, Hostname: "." + parentDomain}, nil

	case hasArbitraryWildcard:
		re, err := starToRegex(hostnameOrIP)
		if err != nil {
			return nil, fmt.Errorf("parse wildcard matcher: %w", err)
		}

		return &hostMatcher{HostnameRE: re, originalWildcardHostname: hostnameOrIP}, nil
	default:
		if resolveIPs {
			resolvedIPs, _ = hostMatcherLookupFunction(hostnameOrIP, dnsTimeout)
		}

		return &hostMatcher{IPs: resolvedIPs, Hostname: hostnameOrIP}, nil
	}
}

func asHostMatchers(hostnamesOrIPs []string, resolveIPs bool, dnsTimeout time.Duration) ([]*hostMatcher, error) {
	hosts := make([]*hostMatcher, 0, len(hostnamesOrIPs))

	for _, hostnameOrIP := range hostnamesOrIPs {
		hostMatcher, err := newHostMatcher(strings.TrimSpace(hostnameOrIP), resolveIPs, dnsTimeout)
		if err != nil {
			return nil, err
		}

		hosts = append(hosts, hostMatcher)
	}

	return hosts, nil
}

func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimRight(hostname, "."))
}

// Matches determines whether or not the host matches any of the provided hostnames.
func (h *hostMatcher) MatchesAnyHostname(hostnames ...string) bool {
	for _, otherHostname := range hostnames {
		otherHostname = normalizeHostname(otherHostname)

		switch {
		case h.HostnameRE != nil:
			if h.HostnameRE.MatchString(otherHostname) {
				return true
			}

		case h.Hostname == ".":
			if !strings.Contains(otherHostname, ".") {
				return true
			}
		case h.Hostname != "":
			// hostname matches directly
			if h.Hostname == otherHostname {
				return true
			}

			// domain or subdomain matches
			if strings.HasPrefix(h.Hostname, ".") &&
				(strings.HasSuffix(otherHostname, h.Hostname) || "."+otherHostname == h.Hostname) {
				return true
			}
		}
	}

	return false
}

func (h *hostMatcher) String() string {
	hostname := h.Hostname
	if hostname == "" {
		hostname = h.originalWildcardHostname
	}

	if len(h.IPs) == 0 && hostname == "" {
		return "no host"
	}

	if hostname == "." {
		return "<local hostnames>"
	}

	if strings.HasPrefix(hostname, ".") {
		hostname = "*" + hostname + ", " + strings.TrimLeft(hostname, ".")
	}

	ipStrings := make([]string, 0, len(h.IPs))

	for _, ip := range h.IPs {
		ipStrings = append(ipStrings, ip.String())
	}

	ipsString := strings.Join(ipStrings, ", ")

	if hostname == "" {
		return ipsString
	}

	if len(h.IPs) == 0 {
		return hostname
	}

	return fmt.Sprintf("%s (%s)", hostname, ipsString)
}

type spoofTypes struct {
	A    bool
	AAAA bool
	ANY  bool
	SOA  bool
}

func parseSpoofTypes(spoofTypesStrings []string) (*spoofTypes, error) {
	if len(spoofTypesStrings) == 0 {
		return nil, nil //nolint:nilnil
	}

	st := &spoofTypes{}

	for _, spoofType := range spoofTypesStrings {
		switch strings.ToLower(spoofType) {
		case "a":
			st.A = true
		case "aaaa":
			st.AAAA = true
		case "any":
			st.ANY = true
		case "soa":
			st.SOA = true
		default:
			return nil, fmt.Errorf("unknown query type: %s", spoofType)
		}
	}

	return st, nil
}

func (st *spoofTypes) ShouldSpoof(qType uint16) bool {
	if st == nil {
		return true
	}

	switch {
	case qType == typeNetBios:
		return true
	case qType == dns.TypeA && st.A:
		return true
	case qType == dns.TypeAAAA && st.AAAA:
		return true
	case qType == dns.TypeANY && st.ANY:
		return true
	case qType == dns.TypeSOA && st.SOA:
		return true
	default:
		return false
	}
}

func containsPeer(hosts []*hostMatcher, peer peerInfo) bool {
	for _, host := range hosts {
		if host.MatchesAnyHostname(peer.Hostnames...) {
			return true
		}

		for _, ip := range host.IPs {
			if peer.IP.Equal(ip) {
				return true
			}
		}
	}

	return false
}

func containsIP(haystack []*hostMatcher, needle net.IP) bool {
	for _, el := range haystack {
		for _, ip := range el.IPs {
			if needle.Equal(ip) {
				return true
			}
		}
	}

	return false
}

func containsAnyHostname(haystack []*hostMatcher, needles ...string) bool {
	for _, el := range haystack {
		if el.MatchesAnyHostname(needles...) {
			return true
		}
	}

	return false
}

func lookupIPWithTimeout(hostname string, timeout time.Duration) ([]net.IP, error) {
	if hostname == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))

	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}

	return ips, nil
}

var starReplacerRE = regexp.MustCompile(`(?:\\\*)+`)

func starToRegex(s string) (*regexp.Regexp, error) {
	if !strings.Contains(s, "*") {
		return nil, fmt.Errorf("input does not contain any wildcard symbols (*)")
	}

	return regexp.Compile("^" + starReplacerRE.ReplaceAllString(regexp.QuoteMeta(s), ".*") + "$")
}

type srvMatchers []*srvMatcher

func asSRVMatchers(matcherStrings []string) (srvMatchers, error) {
	matchers := make(srvMatchers, 0, len(matcherStrings))

	for _, m := range matcherStrings {
		matcher := &srvMatcher{
			Service: strings.ToLower(m),
		}

		switch strings.Count(matcher.Service, ":") {
		case 0:
			matcher.isDefaultPort = true

			switch matcher.Service {
			case "ldap":
				matcher.Port = 389
			case "ldaps":
				matcher.Port = 636
			case "http":
				matcher.Port = 80
			case "https":
				matcher.Port = 443
			case "kerberos":
				matcher.Port = 88
			default:
				return nil, fmt.Errorf("missing port in service: %q", m)
			}

			matchers = append(matchers, matcher)
		case 1:
			service, portStr, found := strings.Cut(m, ":")
			if !found {
				return nil, fmt.Errorf("cannot parse service: %q", m)
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("parse port %q in service %q", portStr, m)
			}

			matchers = append(matchers, &srvMatcher{Service: strings.ToLower(service), Port: uint16(port)}) //nolint:gosec
		default:
			return nil, fmt.Errorf("SRV matcher contains more than one colon: %q", m)
		}
	}

	return matchers, nil
}

func (matchers srvMatchers) Contains(service string) bool {
	service, _, _ = strings.Cut(service, ".")

	for _, m := range matchers {
		if m.Matches(service) {
			return true
		}
	}

	return false
}

func (matchers srvMatchers) String() string {
	elements := make([]string, 0, len(matchers))

	for _, m := range matchers {
		switch {
		case m.isDefaultPort:
			elements = append(elements, m.Service)
		default:
			elements = append(elements, fmt.Sprintf("%s:%d", m.Service, m.Port))
		}
	}

	return strings.Join(elements, ", ")
}

func (matchers srvMatchers) Get(service string) *srvMatcher {
	service, _, _ = strings.Cut(service, ".")

	for _, m := range matchers {
		if m.Matches(service) {
			return m
		}
	}

	return nil
}

type srvMatcher struct {
	Service       string
	Port          uint16
	isDefaultPort bool
}

func (sm *srvMatcher) Matches(service string) bool {
	service, _, _ = strings.Cut(service, ".")

	return strings.EqualFold(strings.TrimPrefix(sm.Service, "_"), strings.TrimPrefix(service, "_"))
}
