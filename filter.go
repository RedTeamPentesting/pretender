package main

import (
	"fmt"
	"net"
	"strings"
)

const isatapHostname = "isatap"

func containsDomain(haystack []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSuffix(strings.TrimRight(needle, "."), ".local"))

	for _, el := range haystack {
		el := strings.ToLower(strings.TrimRight(el, "."))

		if strings.HasPrefix(el, ".") && strings.HasSuffix(needle, strings.TrimLeft(el, ".")) {
			return true
		} else if strings.EqualFold(el, needle) {
			return true
		}
	}

	return false
}

func shouldRespondToNameResolutionQuery(config Config, host string, from net.IP) bool {
	if config.DryMode {
		return false
	}

	if strings.HasPrefix(strings.ToLower(host), isatapHostname) {
		return false
	}

	if len(config.SpoofFor) > 0 && !containsIP(config.SpoofFor, from) {
		return false
	}

	if len(config.DontSpoofFor) > 0 && containsIP(config.DontSpoofFor, from) {
		return false
	}

	if len(config.Spoof) > 0 && !containsDomain(config.Spoof, host) {
		return false
	}

	if len(config.DontSpoof) > 0 && containsDomain(config.DontSpoof, host) {
		return false
	}

	return true
}

func shouldRespondToDHCP(config Config, from peerInfo) bool {
	if config.DryMode {
		return false
	}

	if len(from.Hostnames) == 0 && config.IgnoreDHCPv6NoFQDN {
		return false
	}

	if len(config.SpoofFor) > 0 && !containsPeer(config.SpoofFor, from) {
		return false
	}

	if len(config.DontSpoofFor) > 0 && containsPeer(config.DontSpoofFor, from) {
		return false
	}

	return true
}

type hostMatcher struct {
	IPs      []net.IP
	Hostname string
}

var hostMatcherLookupFunction = net.LookupIP

func newHostMatcher(hostnameOrIP string) (*hostMatcher, error) {
	ip := net.ParseIP(hostnameOrIP)
	if ip != nil { // hostnameOrIP is an IP
		return &hostMatcher{IPs: []net.IP{ip}}, nil
	}

	// domain is a wildcard
	if strings.HasPrefix(hostnameOrIP, ".") {
		return &hostMatcher{Hostname: hostnameOrIP}, nil
	}

	// hostnameOrIP is not an IP
	ips, err := hostMatcherLookupFunction(hostnameOrIP)
	if err != nil {
		return nil, err
	}

	return &hostMatcher{
		IPs:      ips,
		Hostname: hostnameOrIP,
	}, nil
}

func asHostMatchers(hostnamesOrIPs []string) ([]*hostMatcher, error) {
	hosts := make([]*hostMatcher, 0, len(hostnamesOrIPs))

	for _, hostnameOrIP := range hostnamesOrIPs {
		host, err := newHostMatcher(hostnameOrIP)
		if err != nil {
			return nil, err
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimRight(hostname, "."))
}

// Matches determines whether or not the host matches any of the provided hostnames.
func (h *hostMatcher) MatchesAnyHostname(hostnames ...string) bool {
	if h.Hostname == "" {
		return false
	}

	thisHostname := normalizeHostname(h.Hostname)

	for _, hostname := range hostnames {
		otherHostname := normalizeHostname(hostname)

		// hostname matches
		if thisHostname == otherHostname {
			return true
		}

		// subdomain matches
		if strings.HasPrefix(thisHostname, ".") && strings.HasSuffix(otherHostname, thisHostname) {
			return true
		}
	}

	return false
}

func (h *hostMatcher) String() string {
	if len(h.IPs) == 0 && h.Hostname == "" {
		return "no host"
	}

	ipStrings := make([]string, 0, len(h.IPs))

	for _, ip := range h.IPs {
		ipStrings = append(ipStrings, ip.String())
	}

	ipsString := strings.Join(ipStrings, ", ")

	if h.Hostname == "" {
		return ipsString
	}

	if len(h.IPs) == 0 {
		return h.Hostname
	}

	return fmt.Sprintf("%s (%s)", h.Hostname, ipsString)
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
