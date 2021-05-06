package main

import (
	"net"
	"strings"
)

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

func containsIP(haystack []net.IP, needle net.IP) bool {
	for _, el := range haystack {
		if net.IP.Equal(el, needle) {
			return true
		}
	}

	return false
}

func filterDNS(config Config, host string, from net.IP) bool {
	if config.DryMode {
		return false
	}

	if strings.HasPrefix(host, "ISATAP") {
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

func filterDHCP(config Config, from net.IP) bool {
	if len(config.SpoofFor) > 0 && containsIP(config.SpoofFor, from) {
		return false
	}

	if len(config.DontSpoofFor) > 0 && containsIP(config.DontSpoofFor, from) {
		return false
	}

	return true
}
