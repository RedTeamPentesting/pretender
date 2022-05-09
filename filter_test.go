package main

import (
	"net"
	"strconv"
	"testing"
)

func TestFilterNameResolutionQuery(t *testing.T) {
	someIP := mustParseIP(t, "10.1.2.3")

	testCases := []struct {
		TestName     string
		SpoofFor     []string
		DontSpoofFor []string
		Spoof        []string
		DontSpoof    []string
		DryMode      bool

		Host string
		From net.IP

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
				SpoofFor:     spoofFor,
				DontSpoofFor: dontSpoofFor,
				Spoof:        testCase.Spoof,
				DontSpoof:    testCase.DontSpoof,
				DryMode:      testCase.DryMode,
			}

			shouldRespond := shouldRespondToNameResolutionQuery(cfg,
				normalizedName(testCase.Host), testCase.From)
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

			shouldRespond := shouldRespondToDHCP(cfg,
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
