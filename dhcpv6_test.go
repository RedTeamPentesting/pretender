package main

import (
	"bytes"
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

func testDHCPv6Response(tb testing.TB, requestFileName string, responseFileName string) {
	tb.Helper()

	clientAddr := &net.UDPAddr{IP: mustParseIP(tb, "fe80::2"), Port: 1234}
	solicit := readDHCPv6Message(tb, requestFileName)
	config := Config{
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
