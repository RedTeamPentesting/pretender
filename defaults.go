package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	// vendors can set the following values to tweak the default configuration
	// during compilation as with -ldflags "-X main.vendorInterface=eth1".

	vendorInterface = ""
	vendorRelayIPv4 = ""
	vendorRelayIPv6 = ""

	vendorNoDHCPv6DNSTakeover   = ""
	vendorNoMDNS                = ""
	vendorNoNetBIOS             = ""
	vendorNoLLMNR               = ""
	vendorNoLocalNameResolution = ""
	vendorNoRA                  = ""

	vendorSpoof        = ""
	vendorDontSpoof    = ""
	vendorSpoofFor     = ""
	vendorDontSpoofFor = ""
	vendorDryMode      = ""

	vendorTTL           = ""
	vendorLeaseLifetime = ""
	vendorRAPeriod      = ""

	vendorStopAfter    = ""
	vendorVerbose      = ""
	vendorNoColor      = ""
	vendorNoTimestamps = ""
	vendorNoHostInfo   = ""
)

var (
	defaultInterface = vendorInterface
	defaultRelayIPv4 = forceIP(vendorRelayIPv4, nil)
	defaultRelayIPv6 = forceIP(vendorRelayIPv6, nil)

	defaultNoDHCPv6DNSTakeover   = forceBool(vendorNoDHCPv6DNSTakeover, false)
	defaultNoMDNS                = forceBool(vendorNoMDNS, false)
	defaultNoNetBIOS             = forceBool(vendorNoNetBIOS, false)
	defaultNoLLMNR               = forceBool(vendorNoLLMNR, false)
	defaultNoLocalNameResolution = forceBool(vendorNoLocalNameResolution, false)
	defaultNoRA                  = forceBool(vendorNoRA, false)

	defaultSpoof        = forceStrings(vendorSpoof, nil)
	defaultDontSpoof    = forceStrings(vendorDontSpoof, nil)
	defaultSpoofFor     = forceIPs(vendorSpoofFor, nil)
	defaultDontSpoofFor = forceIPs(vendorDontSpoofFor, nil)
	defaultDryMode      = forceBool(vendorDryMode, false)

	defaultTTL           = forceDuration(vendorTTL, dnsDefaultTTL)
	defaultLeaseLifetime = forceDuration(vendorLeaseLifetime, dhcpv6DefaultValidLifetime)
	defaultRAPeriod      = forceDuration(vendorRAPeriod, raDefaultPeriod)

	defaultStopAfter    = forceDuration(vendorStopAfter, 0)
	defaultVerbose      = forceBool(vendorVerbose, false)
	defaultNoColor      = forceBool(vendorNoColor, false)
	defaultNoTimestamps = forceBool(vendorNoTimestamps, false)
	defaultNoHostInfo   = forceBool(vendorNoHostInfo, false)
)

func forceIP(ipString string, fallbackIP net.IP) net.IP {
	if ipString == "" {
		return fallbackIP
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		panic(fmt.Sprintf("cannot parse IP %q", ipString))
	}

	return ip
}

func forceStrings(input string, fallbackStrings []string) []string {
	if input == "" {
		return fallbackStrings
	}

	res := make([]string, 0, len(input))

	for _, s := range strings.Split(input, ",") {
		res = append(res, strings.TrimSpace(s))
	}

	return res
}

func forceBool(boolString string, fallbackBool bool) bool { //nolint:unparam
	switch strings.ToLower(boolString) {
	case "":
		return fallbackBool
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		panic(fmt.Sprintf("cannot parse bool %q", boolString))
	}
}

func forceIPs(ipsString string, fallbackIPs []net.IP) []net.IP {
	if ipsString == "" {
		return fallbackIPs
	}

	parts := strings.Split(ipsString, ",")

	ips := make([]net.IP, 0, len(parts))

	for _, part := range parts {
		ips = append(ips, forceIP(strings.TrimSpace(part), nil))
	}

	return ips
}

func forceDuration(durationString string, fallbackDuration time.Duration) time.Duration {
	if durationString == "" {
		return fallbackDuration
	}

	d, err := time.ParseDuration(durationString)
	if err != nil {
		panic(fmt.Sprintf("cannot parse duration %q", durationString))
	}

	return d
}
