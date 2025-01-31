package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const fallbackLogFileEnvironmentVariable = "PRETENDER_LOG_FILE"

var (
	// vendors can set the following values to tweak the default configuration
	// during compilation as with -ldflags "-X main.vendorInterface=eth1".

	vendorInterface      = ""
	vendorRelayIPv4      = ""
	vendorRelayIPv6      = ""
	vendorSOAHostname    = ""
	vendorSpoofLLMNRName = ""

	vendorNoDHCPv6DNSTakeover   = ""
	vendorNoDHCPv6              = ""
	vendorNoDNS                 = ""
	vendorNoMDNS                = ""
	vendorNoNetBIOS             = ""
	vendorNoLLMNR               = ""
	vendorNoLocalNameResolution = ""
	vendorNoIPv6LNR             = ""
	vendorNoRA                  = ""
	vendorNoRADNS               = ""

	vendorSpoof                  = ""
	vendorDontSpoof              = ""
	vendorSpoofFor               = ""
	vendorDontSpoofFor           = ""
	vendorSpoofTypes             = ""
	vendorIgnoreDHCPv6NoFQDN     = ""
	vendorIgnoreNonMicrosoftDHCP = ""
	vendorDelegateIgnoredTo      = ""
	vendorDontSendEmptyReplies   = ""
	vendorDryMode                = ""
	vendorDryWithDHCPMode        = ""
	vendorStatelessRA            = ""

	vendorTTL              = ""
	vendorLeaseLifetime    = ""
	vendorRARouterLifetime = ""
	vendorRAPeriod         = ""
	vendorDNSTimeout       = ""

	vendorStopAfter      = ""
	vendorVerbose        = ""
	vendorNoColor        = ""
	vendorNoTimestamps   = ""
	vendorLogFileName    = ""
	vendorNoHostInfo     = ""
	vendorHideIgnored    = ""
	vendorRedirectStderr = ""
	vendorListInterfaces = ""
)

var (
	defaultInterface      = vendorInterface
	defaultRelayIPv4      = forceIP(vendorRelayIPv4, nil)
	defaultRelayIPv6      = forceIP(vendorRelayIPv6, nil)
	defaultSOAHostname    = vendorSOAHostname
	defaultSpoofLLMNRName = vendorSpoofLLMNRName

	defaultNoDHCPv6DNSTakeover   = forceBool(vendorNoDHCPv6DNSTakeover, false)
	defaultNoDHCPv6              = forceBool(vendorNoDHCPv6, false)
	defaultNoDNS                 = forceBool(vendorNoDNS, false)
	defaultNoMDNS                = forceBool(vendorNoMDNS, false)
	defaultNoNetBIOS             = forceBool(vendorNoNetBIOS, false)
	defaultNoLLMNR               = forceBool(vendorNoLLMNR, false)
	defaultNoLocalNameResolution = forceBool(vendorNoLocalNameResolution, false)
	defaultNoIPv6LNR             = forceBool(vendorNoIPv6LNR, false)
	defaultNoRA                  = forceBool(vendorNoRA, false)
	defaultNoRADNS               = forceBool(vendorNoRADNS, false)

	defaultSpoof                  = forceStrings(vendorSpoof)
	defaultDontSpoof              = forceStrings(vendorDontSpoof)
	defaultSpoofFor               = forceStrings(vendorSpoofFor)
	defaultDontSpoofFor           = forceStrings(vendorDontSpoofFor)
	defaultSpoofTypes             = forceStrings(vendorSpoofTypes)
	defaultIgnoreDHCPv6NoFQDN     = forceBool(vendorIgnoreDHCPv6NoFQDN, false)
	defaultIgnoreNonMicrosoftDHCP = forceBool(vendorIgnoreNonMicrosoftDHCP, false)
	defaultDelegateIgnoredTo      = vendorDelegateIgnoredTo
	defaultDontSendEmptyReplies   = forceBool(vendorDontSendEmptyReplies, false)
	defaultDryMode                = forceBool(vendorDryMode, false)
	defaultDryWithDHCPMode        = forceBool(vendorDryWithDHCPMode, false)
	defaultStatelessRA            = forceBool(vendorStatelessRA, false)

	defaultTTL              = forceDuration(vendorTTL, dnsDefaultTTL)
	defaultLeaseLifetime    = forceDuration(vendorLeaseLifetime, dhcpv6DefaultValidLifetime)
	defaultRARouterLifetime = forceDuration(vendorRARouterLifetime, raDefaultRouterLifetime)
	defaultRAPeriod         = forceDuration(vendorRAPeriod, raDefaultPeriod)
	defaultDNSTimeout       = forceDuration(vendorDNSTimeout, defaultLookupTimeout)

	defaultStopAfter      = forceDuration(vendorStopAfter, 0)
	defaultVerbose        = forceBool(vendorVerbose, false)
	defaultNoColor        = forceBool(vendorNoColor, false)
	defaultNoTimestamps   = forceBool(vendorNoTimestamps, false)
	defaultHideIgnored    = forceBool(vendorHideIgnored, false)
	defaultLogFileName    = fromEnvironmentIfEmpty(vendorLogFileName, fallbackLogFileEnvironmentVariable)
	defaultNoHostInfo     = forceBool(vendorNoHostInfo, false)
	defaultRedirectStderr = forceBool(vendorRedirectStderr, false)
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

func fromEnvironmentIfEmpty(primaryValue string, fallbackEnvVariable string) string {
	if primaryValue != "" {
		return primaryValue
	}

	return os.Getenv(fallbackEnvVariable)
}
