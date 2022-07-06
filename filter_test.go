package main

import (
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"
)

func TestFilterNameResolutionQuery(t *testing.T) { // nolint:maintidx
	someIP := mustParseIP(t, "10.1.2.3")

	testCases := []struct {
		TestName     string
		SpoofFor     []string
		DontSpoofFor []string
		Spoof        []string
		DontSpoof    []string
		SpoofTypes   []string
		DryMode      bool

		Host          string
		QueryType     uint16 // defaults to A
		From          net.IP
		FromHostnames []string

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
			Host:          "test",
			QueryType:     typeNetBios,
			From:          someIP,
			SpoofTypes:    []string{"A", "AAAA"},
			ShouldRespond: true,
		},
	}

	hostMatcherLookupFunction = func(host string) ([]net.IP, error) {
		switch host {
		case "somehost":
			return []net.IP{mustParseIP(t, "192.168.0.5")}, nil
		default:
			return nil, nil
		}
	}

	for i, testCase := range testCases {
		testCase := testCase

		testName := testCase.TestName
		if testName == "" {
			testName = strconv.Itoa(i)
		}

		t.Run("test_"+testName, func(t *testing.T) {
			spoofFor, err := asHostMatchers(testCase.SpoofFor)
			if err != nil {
				t.Fatalf("convert SpoofFor to host matchers: %v", err)
			}

			dontSpoofFor, err := asHostMatchers(testCase.DontSpoofFor)
			if err != nil {
				t.Fatalf("convert DontSpoofFor to host matchers: %v", err)
			}

			types, err := parseSpoofTypes(testCase.SpoofTypes)
			if err != nil {
				t.Fatalf("parse spoof types: %v", err)
			}

			cfg := Config{
				SpoofFor:     spoofFor,
				DontSpoofFor: dontSpoofFor,
				Spoof:        testCase.Spoof,
				DontSpoof:    testCase.DontSpoof,
				DryMode:      testCase.DryMode,
				SpoofTypes:   types,
			}

			if testCase.QueryType == 0 {
				testCase.QueryType = dns.TypeA
			}

			shouldRespond, _ := shouldRespondToNameResolutionQuery(cfg,
				normalizedName(testCase.Host), testCase.QueryType, testCase.From, testCase.FromHostnames)
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
		TestName           string
		SpoofFor           []string
		DontSpoofFor       []string
		IgnoreDHCPv6NoFQDN bool
		DryMode            bool

		PeerIP        net.IP
		PeerHostnames []string

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
	}

	hostMatcherLookupFunction = func(host string) ([]net.IP, error) {
		switch host {
		case "somehost":
			return []net.IP{mustParseIP(t, "192.168.0.5")}, nil
		default:
			return nil, nil
		}
	}

	for i, testCase := range testCases {
		testCase := testCase

		testName := testCase.TestName
		if testName == "" {
			testName = strconv.Itoa(i)
		}

		t.Run("test_"+testName, func(t *testing.T) {
			spoofFor, err := asHostMatchers(testCase.SpoofFor)
			if err != nil {
				t.Fatalf("convert SpoofFor to host matchers: %v", err)
			}

			dontSpoofFor, err := asHostMatchers(testCase.DontSpoofFor)
			if err != nil {
				t.Fatalf("convert DontSpoofFor to host matchers: %v", err)
			}

			cfg := Config{
				SpoofFor:           spoofFor,
				DontSpoofFor:       dontSpoofFor,
				DryMode:            testCase.DryMode,
				IgnoreDHCPv6NoFQDN: testCase.IgnoreDHCPv6NoFQDN,
			}

			shouldRespond, _ := shouldRespondToDHCP(cfg,
				peerInfo{IP: testCase.PeerIP, Hostnames: testCase.PeerHostnames})
			if shouldRespond != testCase.ShouldRespond {
				t.Errorf("shouldRespondToDHCP returned %v instead of %v",
					shouldRespond, testCase.ShouldRespond)
			}
		})
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
