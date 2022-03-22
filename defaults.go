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
	vendorNoIPv6LNR             = ""

	vendorSpoof              = ""
	vendorDontSpoof          = ""
	vendorSpoofFor           = ""
	vendorDontSpoofFor       = ""
	vendorIgnoreDHCPv6NoFQDN = ""
	vendorDryMode            = ""

	vendorTTL           = ""
	vendorLeaseLifetime = ""
	vendorRAPeriod      = ""

	vendorStopAfter      = ""
	vendorVerbose        = ""
	vendorNoColor        = ""
	vendorNoTimestamps   = ""
	vendorLogFileName    = ""
	vendorNoHostInfo     = ""
	vendorHideIgnored    = ""
	vendorListInterfaces = ""
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
	defaultNoIPv6LNR             = forceBool(vendorNoIPv6LNR, false)

	defaultSpoof              = forceStrings(vendorSpoof)
	defaultDontSpoof          = forceStrings(vendorDontSpoof)
	defaultSpoofFor           = forceStrings(vendorSpoofFor)
	defaultDontSpoofFor       = forceStrings(vendorDontSpoofFor)
	defaultIgnoreDHCPv6NoFQDN = forceBool(vendorIgnoreDHCPv6NoFQDN, false)
	defaultDryMode            = forceBool(vendorDryMode, false)

	defaultTTL           = forceDuration(vendorTTL, dnsDefaultTTL)
	defaultLeaseLifetime = forceDuration(vendorLeaseLifetime, dhcpv6DefaultValidLifetime)
	defaultRAPeriod      = forceDuration(vendorRAPeriod, raDefaultPeriod)

	defaultStopAfter      = forceDuration(vendorStopAfter, 0)
	defaultVerbose        = forceBool(vendorVerbose, false)
	defaultNoColor        = forceBool(vendorNoColor, false)
	defaultNoTimestamps   = forceBool(vendorNoTimestamps, false)
	defaultHideIgnored    = forceBool(vendorHideIgnored, false)
	defaultLogFileName    = vendorLogFileName
	defaultNoHostInfo     = forceBool(vendorNoHostInfo, false)
	defaultListInterfaces = forceBool(vendorListInterfaces, false)
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

func forceStrings(input string) []string {
	if input == "" {
		return nil
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
