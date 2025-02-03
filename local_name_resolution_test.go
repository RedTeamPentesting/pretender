package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLLMNR(t *testing.T) {
	testReply(t, "testdata/llmnr_request.bin", "testdata/llmnr_reply.bin")
}

func TestMDNS(t *testing.T) {
	testReply(t, "testdata/mdns_request.bin", "testdata/mdns_reply.bin")
}

func TestNetBIOS(t *testing.T) {
	relayIP := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}
	request := readNameServiceMessage(t, "testdata/netbios_request.bin")
	expectedReply := readFile(t, "testdata/netbios_reply.bin")
	cfg := &Config{RelayIPv4: relayIP, TTL: 60 * time.Second}

	reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeNetBIOS, nil)
	if reply == nil {
		t.Fatalf("no message was created")
	}

	if !reply.Authoritative {
		t.Fatalf("reply is not authoritative such that it will not be considered by Windows")
	}

	if len(reply.Answer) != 1 {
		t.Fatalf("received %d answers instead of 1", len(reply.Answer))
	}

	answer, ok := reply.Answer[0].(*dns.NIMLOC)
	if !ok {
		t.Fatalf("wrong answer type: %T", reply.Answer[0])
	}

	expectedLocator := encodeNetBIOSLocator(relayIP)
	if answer.Locator != expectedLocator {
		t.Fatalf("unexpected locator: got %q instead of %q", answer.Locator, expectedLocator)
	}

	if answer.Hdr.Ttl != uint32(cfg.TTL.Seconds()) {
		t.Fatalf("unexpected TTL: got %ds instead of %ds", answer.Hdr.Ttl, uint32(cfg.TTL.Seconds()))
	}

	if answer.Hdr.Name != request.Question[0].Name {
		t.Fatalf("%q was echoed instead of question name %q", answer.Hdr.Name, reply.Question[0].Name)
	}

	if answer.Hdr.Rrtype != typeNetBios {
		t.Fatalf("unexpected type: got %s instead of NIMLOC/NetBIOS", dnsQueryType(answer.Hdr.Rrtype))
	}

	if answer.Hdr.Class != dns.ClassINET {
		t.Fatalf("unexpected class: got %d instead of %d", answer.Hdr.Class, dns.ClassINET)
	}

	if reply.CheckingDisabled {
		t.Fatalf("checking disabled should be false in NetBIOS reply")
	}

	if reply.Question != nil {
		t.Fatalf("NetBIOS reply cannot include question")
	}

	replyBuffer, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}

	if !bytes.Equal(replyBuffer, expectedReply) {
		t.Fatalf("reply bytes do not match")
	}
}

func TestLLMNRResponseNameSpoofing(t *testing.T) {
	relayIP := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}
	request := readNameServiceMessage(t, "testdata/llmnr_request.bin")
	cfg := &Config{RelayIPv6: relayIP, TTL: 60 * time.Second, SpoofResponseName: "spoofedname"}

	reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeLLMNR, nil)
	if reply == nil {
		t.Fatalf("no message was created")
	}

	if len(reply.Question) != 1 {
		t.Fatalf("reply does %d questions instead of 1", len(reply.Question))
	}

	if reply.Question[0].Name != "test." {
		t.Fatalf("reply contains question %q instead of %q", reply.Question[0].Name, "test.")
	}

	if len(reply.Answer) != 1 {
		t.Fatalf("reply contains %d answers instead of 1", len(reply.Answer))
	}

	if reply.Answer[0].Header().Name != "spoofedname." {
		t.Fatalf("reply answer name is %q instead of %q", reply.Answer[0].Header().Name, "spoofedname.")
	}
}

func TestMDNSNoResponseNameSpoofing(t *testing.T) {
	relayIP := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}
	request := readNameServiceMessage(t, "testdata/llmnr_request.bin")
	cfg := &Config{RelayIPv6: relayIP, TTL: 60 * time.Second, SpoofResponseName: "spoofedname"}

	reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeMDNS, nil)
	if reply != nil {
		t.Fatalf("an mDNS response was created even though mDNS does not support response name spoofing")
	}
}

func TestNetBIOSNoResponseNameSpoofing(t *testing.T) {
	relayIP := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}
	request := readNameServiceMessage(t, "testdata/llmnr_request.bin")
	cfg := &Config{RelayIPv6: relayIP, TTL: 60 * time.Second, SpoofResponseName: "spoofedname"}

	reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeNetBIOS, nil)
	if reply != nil {
		t.Fatalf("an NetBIOS response was created even though NetBIOS does not support response name spoofing")
	}
}

func TestSubnetBroadcastListenIP(t *testing.T) {
	testCases := []struct {
		Net         string
		BroadcastIP string
	}{
		{"192.168.0.4/24", "192.168.0.255"},
		{"10.0.0.10/23", "10.0.1.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"192.168.5.16/30", "192.168.5.19"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Net, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(testCase.Net)
			if err != nil {
				t.Fatalf("invalid net %q: %v", testCase.Net, err)
			}

			expected := net.ParseIP(testCase.BroadcastIP)
			if expected == nil {
				t.Fatalf("invalid broadcast IP: %s", testCase.BroadcastIP)
			}

			broadcastIP, err := subnetBroadcastListenIP(ipNet)
			if err != nil {
				t.Fatalf("calculating broadcast listen IP: %v", err)
			}

			if !broadcastIP.Equal(expected) {
				t.Fatalf("expected broadcast IP %s for net %s, got %s instead",
					expected, ipNet, broadcastIP)
			}
		})
	}
}

func TestDecodeNetBIOSHostname(t *testing.T) {
	testCases := []struct {
		NetBIOSName string
		Expected    string
	}{
		{NetBIOSName: "FEEFFDFEEIEPFDFECACACACACACACACA.", Expected: "TESTHOST"},

		// different NetBIOS Suffixes
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACAAA.", Expected: "WORKGROUP"}, // workstation name
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACAAB.", Expected: "WORKGROUP"}, // messenger service
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABL.", Expected: "WORKGROUP"}, // domain master browser
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABN.", Expected: "WORKGROUP"}, // master browser
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABO.", Expected: "WORKGROUP"}, // domain service elections
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACACA.", Expected: "WORKGROUP"}, // file service
	}

	for _, testCase := range testCases {
		t.Run(testCase.Expected, func(t *testing.T) {
			decoded := decodeNetBIOSHostname(testCase.NetBIOSName)
			if decoded != testCase.Expected {
				t.Errorf("%s decoded to %s instead of %s",
					testCase.NetBIOSName, decoded, testCase.Expected)
			}
		})
	}
}

func TestNetBIOSEncodeDecode(t *testing.T) {
	hostname := "somehostname"

	netBIOSName := encodeNetBIOSHostname(hostname, 0)

	decodedHostname := decodeNetBIOSHostname(netBIOSName)
	if decodedHostname != hostname {
		t.Errorf("decoded hostname is %q instead of %q", decodedHostname, hostname)
	}

	suffix := decodeNetBIOSSuffix(netBIOSName)
	if suffix != NetBIOSSuffixWorkstationService {
		t.Errorf("decoded suffix is %q instead of %q", suffix, NetBIOSSuffixWorkstationService)
	}
}

func TestDecodeNetBIOSSuffix(t *testing.T) {
	testCases := []struct {
		NetBIOSName string
		Expected    string
	}{
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACAAA.", Expected: NetBIOSSuffixWorkstationService},
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACAAB.", Expected: NetBIOSSuffixWindowsMessengerService},
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABL.", Expected: NetBIOSSuffixDomainMasterBrowser},
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABN.", Expected: NetBIOSSuffixMasterBrowser},
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACABO.", Expected: NetBIOSSuffixBrowserServiceElections},
		{NetBIOSName: "FHEPFCELEHFCEPFFFACACACACACACACA.", Expected: NetBIOSSuffixFileService},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Expected, func(t *testing.T) {
			decoded := decodeNetBIOSSuffix(testCase.NetBIOSName)
			if decoded != testCase.Expected {
				t.Errorf("%s suffix decoded to %q instead of %q",
					testCase.NetBIOSName, decoded, testCase.Expected)
			}
		})
	}
}
