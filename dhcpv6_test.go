package main

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

func TestDHCPv6SolicitAdvertise(t *testing.T) {
	testDHCPv6Response(t, "testdata/dhcpv6_solicit.bin", "testdata/dhcpv6_advertise.bin")
}

func TestDHCPv6SolicitRequestReply(t *testing.T) {
	testDHCPv6Response(t, "testdata/dhcpv6_request.bin", "testdata/dhcpv6_request_reply.bin")
}

func TestDHCPv6SolicitRenewReply(t *testing.T) {
	testDHCPv6Response(t, "testdata/dhcpv6_renew.bin", "testdata/dhcpv6_renew_reply.bin")
}

func TestGenerateDeterministicRandomAddress(t *testing.T) {
	sampleSize := 500

	t.Run("same_input", func(t *testing.T) {
		inputIP := mustParseIP(t, "fe80::9c90:a097:867d:e039")

		reference, err := generateDeterministicRandomAddress(inputIP)
		if err != nil {
			t.Fatalf("generate deterministic random address: %v", err)
		}

		assertLinkLocalIPv6(t, reference)

		for i := 0; i < sampleSize; i++ {
			ip, err := generateDeterministicRandomAddress(inputIP)
			if err != nil {
				t.Fatalf("generate deterministic random address: %v", err)
			}

			assertLinkLocalIPv6(t, ip)

			if !ip.Equal(reference) {
				t.Errorf("a different address was generated in iteration %d", i)
			}
		}
	})

	t.Run("different_input", func(t *testing.T) {
		seen := map[string]bool{}

		for i := 0; i < sampleSize; i++ {
			randomPart := make([]byte, net.IPv6len/2)

			binary.LittleEndian.PutUint64(randomPart, rand.Uint64()) //nolint:gosec

			inputIP := append([]byte{}, dhcpv6LinkLocalPrefix...)
			inputIP = append(inputIP, randomPart...)

			ip, err := generateDeterministicRandomAddress(net.IP(inputIP))
			if err != nil {
				t.Fatalf("generate deterministic random address: %v", err)
			}

			assertLinkLocalIPv6(t, ip)

			if seen[ip.String()] {
				t.Errorf("a dublicate address was generated in iteration %d", i)
			}

			seen[ip.String()] = true
		}
	})
}

func TestNewPeerInfo(t *testing.T) {
	solicit, err := readDHCPv6Message(t, "testdata/dhcpv6_solicit.bin").GetInnerMessage()
	if err != nil {
		t.Fatalf("get inner message: %v", err)
	}

	sourceAddr := &net.UDPAddr{IP: mustParseIP(t, "fe80::d422:2ab:8bf4:7381"), Port: 1234}
	expectedHostname := "win10vm"

	peerInfo := newPeerInfo(sourceAddr, solicit)

	if !peerInfo.IP.Equal(sourceAddr.IP) {
		t.Errorf("peer info contains IP %s instead of %s", peerInfo.IP, sourceAddr.IP)
	}

	if peerInfo.EnterpriseNumber != 311 {
		t.Errorf("peer enterprise number is %d instead of %d", peerInfo.EnterpriseNumber, 311)
	}

	if len(peerInfo.Hostnames) != 1 {
		t.Fatalf("peer info contains %d hostnames instead of one", len(peerInfo.Hostnames))
	}

	if peerInfo.Hostnames[0] != expectedHostname {
		t.Errorf("hostname is %q instead of %q", peerInfo.Hostnames[0], expectedHostname)
	}
}

func testDHCPv6Response(tb testing.TB, requestFileName string, responseFileName string) {
	tb.Helper()

	clientAddr := &net.UDPAddr{IP: mustParseIP(tb, "fe80::2"), Port: 1234}
	solicit := readDHCPv6Message(tb, requestFileName)
	config := &Config{
		Interface:     &net.Interface{HardwareAddr: mustParseMAC(tb, "08:00:27:7e:ca:64")},
		LeaseLifetime: dhcpv6DefaultValidLifetime,
		LocalIPv6:     mustParseIP(tb, "fe80::a00:27ff:fe7e:ca64"),
	}

	advertise, err := NewDHCPv6Handler(config, nil).createResponse(clientAddr, solicit)
	if err != nil {
		tb.Fatalf("create response: %v", err)
	}

	expectedAdvertise := readFile(tb, responseFileName)

	if !bytes.Equal(advertise.ToBytes(), expectedAdvertise) {
		tb.Fatalf("advertise bytes do not match")
	}
}

func readDHCPv6Message(tb testing.TB, fileName string) *dhcpv6.Message {
	tb.Helper()

	msg, err := dhcpv6.MessageFromBytes(readFile(tb, fileName))
	if err != nil {
		tb.Fatalf("read DHCPv6 message from bytes: %v", err)
	}

	return msg
}

func mustParseMAC(tb testing.TB, mac string) net.HardwareAddr {
	tb.Helper()

	hwa, err := net.ParseMAC(mac)
	if err != nil {
		tb.Fatalf("parse MAC: %v", err)
	}

	return hwa
}

func assertLinkLocalIPv6(tb testing.TB, ip net.IP) {
	tb.Helper()

	if ip.To4() != nil {
		tb.Fatalf("IP %s is an IPv4 address instead of an IPv6 address", ip)
	}

	if len(ip) != net.IPv6len {
		tb.Fatalf("IP %s contains %d bytes instead of %d bytes (IPv6)",
			ip, len(ip), net.IPv6len)
	}

	if !bytes.Equal(ip[:net.IPv6len/2], dhcpv6LinkLocalPrefix) {
		tb.Fatalf("IP does not have link local prefix: %s", ip)
	}
}
