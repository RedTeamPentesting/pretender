package main

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFilterNameResolutionQuery(t *testing.T) { //nolint:maintidx
	someIP := mustParseIP(t, "10.1.2.3")
	relayIPv4 := mustParseIP(t, "10.0.0.1")
	relayIPv6 := mustParseIP(t, "fe80::1")

	testCases := []struct {
		TestName                    string
		SpoofFor                    []string
		DontSpoofFor                []string
		Spoof                       []string
		DontSpoof                   []string
		SpoofTypes                  []string
		DryMode                     bool
		DryWithDHCPv6Mode           bool
		NoRelayIPv4Configured       bool
		NoRelayIPv6Configured       bool
		SpoofingTemporarilyDisabled bool
		SpoofResponseName           string

		Host          string
		QueryType     uint16 // defaults to A
		From          net.IP
		FromHostnames []string

		HandlerType HandlerType

		ShouldRespond bool
	}{
		{
			TestName:      "regular",
			Host:          "foo",
			From:          someIP,
			ShouldRespond: true,
		},
		{
			TestName:      "istap",
			Host:          isatapHostname,
			From:          someIP,
			ShouldRespond: false,
		},
		{
			TestName:      "dry",
			Host:          "foo",
			DryMode:       true,
			From:          someIP,
			ShouldRespond: false,
		},
		{
			TestName:          "dry with dhcp",
			Host:              "foo",
			DryWithDHCPv6Mode: true,
			From:              someIP,
			ShouldRespond:     false,
		},
		{
			Host:          "foo",
			Spoof:         []string{"foo"},
			SpoofFor:      []string{someIP.String()},
			DryMode:       true,
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "foo",
			Spoof:         []string{"foo", "oof"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "oof",
			Spoof:         []string{"foo", "oof"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "test",
			SpoofFor:      []string{"anotherhost"},
			From:          someIP,
			FromHostnames: []string{"anotherhost", "test"},
			ShouldRespond: true,
		},
		{
			Host:          "test",
			DontSpoofFor:  []string{"anotherhost"},
			From:          someIP,
			FromHostnames: []string{"anotherhost", "test"},
			ShouldRespond: false,
		},
		{
			Host:          "test",
			SpoofFor:      []string{".anotherhost"},
			From:          someIP,
			FromHostnames: []string{"foo.anotherhost", "test"},
			ShouldRespond: true,
		},
		{
			Host:          "bar",
			Spoof:         []string{"foo", "oof"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "foo",
			DontSpoof:     []string{"foo", "oof"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "oof",
			DontSpoof:     []string{"foo", "oof"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "bar",
			SpoofFor:      []string{"somehost"}, // resolves to 192.168.0.5
			From:          mustParseIP(t, "192.168.0.5"),
			ShouldRespond: true,
		},
		{
			Host:          "bar",
			SpoofFor:      []string{"192.168.0.5"},
			From:          mustParseIP(t, "192.168.0.5"),
			ShouldRespond: true,
		},
		{
			Host:          "bar",
			DontSpoofFor:  []string{"somehost"}, // resolves to 192.168.0.5
			From:          mustParseIP(t, "192.168.0.5"),
			ShouldRespond: false,
		},
		{
			Host:          "bar",
			SpoofFor:      []string{"x"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "foo.bar",
			Spoof:         []string{"bar"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "foo.bar",
			Spoof:         []string{".bar"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "foo.bar",
			DontSpoof:     []string{"bar"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "foo.bar",
			DontSpoof:     []string{".bar"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "foobar",
			DontSpoof:     []string{"bar"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "foobar",
			DontSpoof:     []string{".bar"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "bar",
			DontSpoof:     []string{".bar"},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			Host:          "bar",
			Spoof:         []string{"bar."},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "bar.",
			Spoof:         []string{"bar"},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "bar.",
			Spoof:         []string{"bar."},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			Host:          "test",
			QueryType:     dns.TypeA,
			From:          someIP,
			SpoofTypes:    []string{"a"},
			ShouldRespond: true,
		},
		{
			Host:          "test",
			QueryType:     dns.TypeA,
			From:          someIP,
			SpoofTypes:    []string{"A"},
			ShouldRespond: true,
		},
		{
			Host:          "test",
			QueryType:     dns.TypeA,
			From:          someIP,
			SpoofTypes:    []string{"SOA"},
			ShouldRespond: false,
		},
		{
			Host:          "test",
			QueryType:     dns.TypeSOA,
			From:          someIP,
			SpoofTypes:    []string{"A", "AAAA", "SOA"},
			ShouldRespond: true,
		},
		{
			Host:          "test",
			QueryType:     dns.TypeSOA,
			From:          someIP,
			SpoofTypes:    []string{"A", "AAAA"},
			ShouldRespond: false,
		},
		{
			TestName:      "NetBIOS unaffected by spoof-types",
			Host:          "test",
			QueryType:     typeNetBios,
			From:          someIP,
			SpoofTypes:    []string{"A", "AAAA"},
			ShouldRespond: true,
		},
		{
			TestName:              "no relay IPv4",
			Host:                  "test",
			QueryType:             dns.TypeA,
			From:                  someIP,
			NoRelayIPv4Configured: true,
			ShouldRespond:         false,
		},
		{
			TestName:              "no relay IPv6",
			Host:                  "test",
			QueryType:             dns.TypeAAAA,
			From:                  someIP,
			NoRelayIPv6Configured: true,
			ShouldRespond:         false,
		},
		{
			TestName:      "dot in spoof matches non-FQDN",
			Host:          "test",
			Spoof:         []string{"."},
			QueryType:     dns.TypeA,
			ShouldRespond: true,
		},
		{
			TestName:      "dot in spoof does not match FQDN",
			Host:          "fqdn.com",
			Spoof:         []string{"."},
			QueryType:     dns.TypeA,
			ShouldRespond: false,
		},
		{
			TestName:      "dot in dont-spoof matches non-FQDN",
			Host:          "test",
			DontSpoof:     []string{"."},
			QueryType:     dns.TypeA,
			ShouldRespond: false,
		},
		{
			TestName:      "dot in dont-spoof does not match FQDN",
			Host:          "fqdn.com",
			DontSpoof:     []string{"."},
			QueryType:     dns.TypeA,
			ShouldRespond: true,
		},
		{
			TestName:      ".local is stripped for mDNS",
			Host:          "_googlecast._tcp.local",
			Spoof:         []string{"._tcp"},
			QueryType:     dns.TypePTR,
			HandlerType:   HandlerTypeMDNS,
			ShouldRespond: true,
		},
		{
			TestName:      ".local does not match for mDNS",
			Host:          "_googlecast._tcp.local",
			Spoof:         []string{".local"},
			QueryType:     dns.TypePTR,
			HandlerType:   HandlerTypeMDNS,
			ShouldRespond: false,
		},
		{
			TestName:      ".local is not stripped for DNS",
			Host:          "foo.local",
			Spoof:         []string{".local"},
			QueryType:     dns.TypeA,
			ShouldRespond: true,
		},
		{
			TestName:      "spaces should be ignored in spoof",
			Host:          "foo",
			Spoof:         []string{" foo "},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			TestName:      "spaces should be ignored dont spoof",
			Host:          "foo",
			DontSpoof:     []string{" foo "},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			TestName:      "spaces should be ignored spoof for",
			Host:          "foo",
			SpoofFor:      []string{" " + someIP.String() + " "},
			From:          someIP,
			ShouldRespond: true,
		},
		{
			TestName:      "spaces should be ignored dont spoof for",
			Host:          "foo",
			DontSpoofFor:  []string{" " + someIP.String() + " "},
			From:          someIP,
			ShouldRespond: false,
		},
		{
			TestName:                    "spoofing temporarily disabled",
			Host:                        "foo",
			From:                        someIP,
			SpoofingTemporarilyDisabled: true,
			ShouldRespond:               false,
		},
		{
			TestName:          "ignore mDNS when response name spoofing is active",
			Host:              "foo",
			From:              someIP,
			SpoofResponseName: "test",
			HandlerType:       HandlerTypeMDNS,
			ShouldRespond:     false,
		},
		{
			TestName:          "ignore NetBIOS when response name spoofing is active",
			Host:              "foo",
			From:              someIP,
			SpoofResponseName: "test",
			HandlerType:       HandlerTypeNetBIOS,
			ShouldRespond:     false,
		},
		{
			TestName:          "do not ignore DNS when response name spoofing is active",
			Host:              "foo",
			From:              someIP,
			SpoofResponseName: "test",
			HandlerType:       HandlerTypeDNS,
			ShouldRespond:     true,
		},
		{
			TestName:          "do not ignore LLMNR when response name spoofing is active",
			Host:              "foo",
			From:              someIP,
			SpoofResponseName: "test",
			HandlerType:       HandlerTypeLLMNR,
			ShouldRespond:     true,
		},
	}

	hostMatcherLookupFunction = func(host string, _ time.Duration) ([]net.IP, error) {
		switch host {
		case "somehost":
			return []net.IP{mustParseIP(t, "192.168.0.5")}, nil
		default:
			return nil, nil
		}
	}

	for i, testCase := range testCases {
		testName := testCase.TestName
		if testName == "" {
			testName = strconv.Itoa(i)
		}

		t.Run("test_"+testName, func(t *testing.T) {
			types, err := parseSpoofTypes(testCase.SpoofTypes)
			if err != nil {
				t.Fatalf("parse spoof types: %v", err)
			}

			stripSpaces(testCase.Spoof)
			stripSpaces(testCase.DontSpoof)

			cfg := &Config{
				SpoofFor:                    testHostMatchers(t, testCase.SpoofFor, defaultLookupTimeout),
				DontSpoofFor:                testHostMatchers(t, testCase.DontSpoofFor, defaultLookupTimeout),
				Spoof:                       testCase.Spoof,
				DontSpoof:                   testCase.DontSpoof,
				DryMode:                     testCase.DryMode,
				DryWithDHCPv6Mode:           testCase.DryWithDHCPv6Mode,
				SpoofTypes:                  types,
				SOAHostname:                 "test",
				SpoofResponseName:           testCase.SpoofResponseName,
				spoofingTemporarilyDisabled: testCase.SpoofingTemporarilyDisabled,
			}

			cfg.setRedundantOptions()

			switch {
			case !testCase.NoRelayIPv4Configured:
				cfg.RelayIPv4 = relayIPv4
			case !testCase.NoRelayIPv6Configured:
				cfg.RelayIPv6 = relayIPv6
			}

			if testCase.QueryType == 0 {
				testCase.QueryType = dns.TypeA
			}

			handlerType := testCase.HandlerType
			if handlerType == HandlerTypeInvalid {
				handlerType = HandlerTypeDNS
			}

			shouldRespond, _ := shouldRespondToNameResolutionQuery(cfg,
				normalizedName(testCase.Host, handlerType),
				testCase.QueryType, testCase.From, testCase.FromHostnames, testCase.HandlerType)
			if shouldRespond != testCase.ShouldRespond {
				t.Errorf("shouldRespondToNameResolutionQuery returned %v instead of %v",
					shouldRespond, testCase.ShouldRespond)
			}
		})
	}
}

func TestFilterDHCP(t *testing.T) {
	someIP := mustParseIP(t, "10.1.2.3")

	testCases := []struct {
		TestName                    string
		SpoofFor                    []string
		DontSpoofFor                []string
		IgnoreDHCPv6NoFQDN          bool
		DryMode                     bool
		DryWithDHCPv6Mode           bool
		SpoofingTemporarilyDisabled bool
		IgnoreNonMicrosoftDHCP      bool

		PeerIP               net.IP
		PeerHostnames        []string
		PeerEnterpriseNumber uint32

		ShouldRespond bool
	}{
		{
			TestName:      "regular",
			PeerIP:        someIP,
			PeerHostnames: []string{"foo"},
			ShouldRespond: true,
		},
		{
			TestName:      "dry",
			DryMode:       true,
			PeerIP:        someIP,
			PeerHostnames: []string{"foo"},
			ShouldRespond: false,
		},
		{
			TestName:          "dry with dhcp",
			DryWithDHCPv6Mode: true,
			PeerIP:            someIP,
			PeerHostnames:     []string{"foo"},
			ShouldRespond:     true,
		},
		{
			TestName:          "dry and drywith dhcp",
			DryMode:           true,
			DryWithDHCPv6Mode: true,
			PeerIP:            someIP,
			PeerHostnames:     []string{"foo"},
			ShouldRespond:     true,
		},
		{
			TestName:      "dry+spooffor",
			SpoofFor:      []string{someIP.String(), "foo"},
			DryMode:       true,
			PeerIP:        someIP,
			PeerHostnames: []string{"foo"},
			ShouldRespond: false,
		},
		{
			TestName:           "fqdn",
			PeerIP:             someIP,
			PeerHostnames:      []string{"foo"},
			IgnoreDHCPv6NoFQDN: true,
			ShouldRespond:      true,
		},
		{
			TestName:           "ignore no fqdn",
			PeerIP:             someIP,
			PeerHostnames:      []string{},
			IgnoreDHCPv6NoFQDN: true,
			ShouldRespond:      false,
		},
		{
			TestName:      "spoof for ignore",
			SpoofFor:      []string{"x"},
			PeerIP:        someIP,
			PeerHostnames: []string{"foo"},
			ShouldRespond: false,
		},
		{
			TestName:      "dont spoof for",
			DontSpoofFor:  []string{"somehost"}, // resolves to 192.168.0.5
			PeerIP:        mustParseIP(t, "192.168.0.5"),
			PeerHostnames: []string{"foo"},
			ShouldRespond: false,
		},
		{
			TestName:      "dont spoof for",
			DontSpoofFor:  []string{"192.168.0.5"},
			PeerIP:        mustParseIP(t, "192.168.0.5"),
			PeerHostnames: []string{"foo"},
			ShouldRespond: false,
		},
		{
			TestName:      "ignore whole domain",
			DontSpoofFor:  []string{".domain"},
			PeerIP:        someIP,
			PeerHostnames: []string{"test.domain"},
			ShouldRespond: false,
		},
		{
			TestName:                    "spoofing temporarily disabled should not affect DHCP",
			PeerIP:                      someIP,
			PeerHostnames:               []string{"foo"},
			SpoofingTemporarilyDisabled: true,
			ShouldRespond:               true,
		},
		{
			TestName:               "ignore non-Microsoft DHCP client",
			PeerIP:                 someIP,
			PeerHostnames:          []string{"foo"},
			IgnoreNonMicrosoftDHCP: true,
			PeerEnterpriseNumber:   1,
			ShouldRespond:          false,
		},
		{
			TestName:               "do not ignore Microsoft DHCP client",
			PeerIP:                 someIP,
			PeerHostnames:          []string{"foo"},
			IgnoreNonMicrosoftDHCP: true,
			PeerEnterpriseNumber:   311,
			ShouldRespond:          true,
		},
	}

	hostMatcherLookupFunction = func(host string, _ time.Duration) ([]net.IP, error) {
		switch host {
		case "somehost":
			return []net.IP{mustParseIP(t, "192.168.0.5")}, nil
		default:
			return nil, nil
		}
	}

	for i, testCase := range testCases {
		testName := testCase.TestName
		if testName == "" {
			testName = strconv.Itoa(i)
		}

		t.Run("test_"+testName, func(t *testing.T) {
			cfg := &Config{
				SpoofFor:                    testHostMatchers(t, testCase.SpoofFor, defaultLookupTimeout),
				DontSpoofFor:                testHostMatchers(t, testCase.DontSpoofFor, defaultLookupTimeout),
				DryMode:                     testCase.DryMode,
				DryWithDHCPv6Mode:           testCase.DryWithDHCPv6Mode,
				IgnoreDHCPv6NoFQDN:          testCase.IgnoreDHCPv6NoFQDN,
				IgnoreNonMicrosoftDHCP:      testCase.IgnoreNonMicrosoftDHCP,
				spoofingTemporarilyDisabled: testCase.SpoofingTemporarilyDisabled,
			}

			cfg.setRedundantOptions()

			peer := peerInfo{
				IP:               testCase.PeerIP,
				Hostnames:        testCase.PeerHostnames,
				EnterpriseNumber: testCase.PeerEnterpriseNumber,
			}

			shouldRespond, _ := shouldRespondToDHCP(cfg, peer)
			if shouldRespond != testCase.ShouldRespond {
				t.Errorf("shouldRespondToDHCP returned %v instead of %v",
					shouldRespond, testCase.ShouldRespond)
			}
		})
	}
}

func TestWildcardHostMatcher(t *testing.T) {
	testCases := []struct {
		Matcher     *hostMatcher
		Hostname    string
		ShouldMatch bool
	}{
		{
			Matcher:     testHostMatcher(t, ".foo", 0),
			Hostname:    "foo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, ".foo", 0),
			Hostname:    "sub.foo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "*foo", 0),
			Hostname:    "foo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "*foo", 0),
			Hostname:    "asdfoo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "*foo", 0),
			Hostname:    "asdfoo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "*foo", 0),
			Hostname:    "fooasd",
			ShouldMatch: false,
		},
		{
			Matcher:     testHostMatcher(t, "*fo*o*", 0),
			Hostname:    "xfoxox",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "***fo****o***", 0),
			Hostname:    "xfoxox",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "***fo****o***", 0),
			Hostname:    "fooo",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "o+", 0),
			Hostname:    "oo",
			ShouldMatch: false,
		},
		{
			Matcher:     testHostMatcher(t, "o+", 0),
			Hostname:    "o+",
			ShouldMatch: true,
		},
		{
			Matcher:     testHostMatcher(t, "[ab]", 0),
			Hostname:    "a",
			ShouldMatch: false,
		},
	}

	for i, testCase := range testCases {
		name := fmt.Sprintf("%d: (%s).MatchesAnyHostname(%q) should return %v",
			i, testCase.Matcher, testCase.Hostname, testCase.ShouldMatch)

		t.Run(name, func(t *testing.T) {
			if testCase.Matcher.MatchesAnyHostname(testCase.Hostname) != testCase.ShouldMatch {
				t.Errorf("unexpected result")
			}
		})
	}
}

func TestMixedWildcardsProducesError(t *testing.T) {
	_, err := newHostMatcher(".foo*bar", 0)
	if err == nil {
		t.Errorf("converting .foo*bar to host matcher did not produce an error")
	}
}

func mustParseIP(tb testing.TB, ip string) net.IP {
	tb.Helper()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		tb.Fatalf("cannot parse IP %s", ip)
	}

	return parsedIP
}

func testHostMatcher(tb testing.TB, hostnameOrIP string, dnsTimeout time.Duration) *hostMatcher {
	tb.Helper()

	m, err := newHostMatcher(hostnameOrIP, dnsTimeout)
	if err != nil {
		tb.Fatalf("build host matcher (hostnameOrIP=%q, dnsTimeout=%v): %v", hostnameOrIP, dnsTimeout, err)
	}

	return m
}

//nolint:unparam
func testHostMatchers(tb testing.TB, hostnameOrIPs []string, dnsTimeout time.Duration) []*hostMatcher {
	tb.Helper()

	m, err := asHostMatchers(hostnameOrIPs, dnsTimeout)
	if err != nil {
		tb.Fatalf("build host matcher (hostnameOrIP=%q, dnsTimeout=%v): %v", hostnameOrIPs, dnsTimeout, err)
	}

	return m
}
