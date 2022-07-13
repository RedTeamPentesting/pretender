package main

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNS(t *testing.T) {
	testResponse(t, "testdata/dns_request.bin", "testdata/dns_response.bin")
}

func TestDNSAny(t *testing.T) {
	request := &dns.Msg{}
	request.SetQuestion("host", dns.TypeANY)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	relayIPv6 := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}
	cfgs := []Config{
		{RelayIPv4: relayIPv4, RelayIPv6: nil, TTL: 60 * time.Second},
		{RelayIPv4: nil, RelayIPv6: relayIPv6, TTL: 60 * time.Second},
		{RelayIPv4: relayIPv4, RelayIPv6: relayIPv6, TTL: 60 * time.Second},
	}

	for i, cfg := range cfgs {
		response := createDNSReplyFromRequest(mockRW, request, nil, cfg)
		if response == nil {
			t.Fatalf("config %d: no message was created", i)

			return // calm down staticcheck linter
		}

		expectedNumberOfAnswers := 0

		if cfg.RelayIPv4 != nil {
			expectedNumberOfAnswers++

			aResponse, ok := getResponseByType(t, response.Answer, dns.TypeA).(*dns.A)
			if !ok {
				t.Fatalf("config %d: unexpected type for A answer: %T", i, aResponse)
			}

			if !aResponse.A.Equal(relayIPv4) {
				t.Fatalf("config %d: response contains A address %s instead of %s",
					i, aResponse.A, relayIPv4)
			}
		}

		if cfg.RelayIPv6 != nil {
			expectedNumberOfAnswers++

			aaaaResponse, ok := getResponseByType(t, response.Answer, dns.TypeAAAA).(*dns.AAAA)
			if !ok {
				t.Fatalf("config %d: unexpected type for A answer: %T", i, aaaaResponse)
			}

			if !aaaaResponse.AAAA.Equal(relayIPv6) {
				t.Fatalf("config %d: response contains AAAA address %s instead of %s",
					i, aaaaResponse.AAAA, relayIPv6)
			}
		}

		if len(response.Answer) != expectedNumberOfAnswers {
			t.Fatalf("config %d: unexpected number of responses: %d instead of %d",
				i, len(response.Answer), expectedNumberOfAnswers)
		}
	}
}

// nolint:cyclop
func testResponse(tb testing.TB, requestFileName string, responseFileName string) {
	tb.Helper()

	relayIPv4 := mustParseIP(tb, "10.0.0.2")
	relayIPv6 := mustParseIP(tb, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(tb, "10.0.0.1")}}
	request := readNameServiceMessage(tb, requestFileName)
	expectedResponse := readFile(tb, responseFileName)
	cfg := Config{RelayIPv4: relayIPv4, RelayIPv6: relayIPv6, TTL: 60 * time.Second}

	response := createDNSReplyFromRequest(mockRW, request, nil, cfg)
	if response == nil {
		tb.Fatalf("no message was created")

		return // calm down staticcheck linter
	}

	if len(response.Answer) == 0 {
		tb.Fatalf("response contains no answers")
	}

	for _, answer := range response.Answer {
		switch a := answer.(type) {
		case *dns.A:
			if !a.A.Equal(relayIPv4) {
				tb.Fatalf("response contains A address %s instead of %s", a.A, relayIPv4)
			}

			if a.Hdr.Rrtype != dns.TypeA {
				tb.Fatalf("unexpected type: got %s instead of %s", dnsQueryType(a.Hdr.Rrtype), dnsQueryType(dns.TypeA))
			}
		case *dns.AAAA:
			if !a.AAAA.Equal(relayIPv6) {
				tb.Fatalf("response contains AAAA address %s instead of %s", a.AAAA, relayIPv6)
			}

			if a.Hdr.Rrtype != dns.TypeAAAA {
				tb.Fatalf("unexpected type: got %s instead of %s", dnsQueryType(a.Hdr.Rrtype), dnsQueryType(dns.TypeAAAA))
			}
		default:
			tb.Fatalf("unexpected response type %T", answer)
		}

		answerHeader := answer.Header()

		if answerHeader.Ttl != uint32(cfg.TTL.Seconds()) {
			tb.Fatalf("unexpected TTL: got %ds instead of %ds", answerHeader.Ttl, uint32(cfg.TTL.Seconds()))
		}

		if answerHeader.Name != request.Question[0].Name {
			tb.Fatalf("%q was echoed instead of question name %q", answerHeader.Name, response.Question[0].Name)
		}

		if answerHeader.Class != dns.ClassINET {
			tb.Fatalf("unexpected class: got %d instead of %d", answerHeader.Class, dns.ClassINET)
		}
	}

	responseBuffer, err := response.Pack()
	if err != nil {
		tb.Fatalf("pack response: %v", err)
	}

	if !bytes.Equal(responseBuffer, expectedResponse) {
		tb.Fatalf("response bytes do not match")
	}
}

func getResponseByType(tb testing.TB, answers []dns.RR, answerType uint16) dns.RR { // nolint:ireturn
	tb.Helper()

	for _, answer := range answers {
		if answer.Header().Rrtype == answerType {
			return answer
		}
	}

	tb.Fatalf("found no answer of type %d", answerType)

	return nil
}

func readNameServiceMessage(tb testing.TB, fileName string) *dns.Msg {
	tb.Helper()

	msg := &dns.Msg{}

	err := msg.Unpack(readFile(tb, fileName))
	if err != nil {
		tb.Fatalf("parse NetBIOS test file: %v", err)
	}

	return msg
}

func readFile(tb testing.TB, fileName string) []byte {
	tb.Helper()

	content, err := os.ReadFile(fileName) // nolint:gosec
	if err != nil {
		tb.Fatalf("read file: %v", err)
	}

	return content
}

type mockResonseWriter struct {
	Local  net.Addr
	Remote net.Addr
}

var _ dns.ResponseWriter = mockResonseWriter{}

func (m mockResonseWriter) LocalAddr() net.Addr {
	return m.Local
}

func (m mockResonseWriter) RemoteAddr() net.Addr {
	return m.Remote
}

func (mockResonseWriter) WriteMsg(*dns.Msg) error {
	return nil
}

func (mockResonseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m mockResonseWriter) Close() error {
	return nil
}

func (m mockResonseWriter) TsigStatus() error {
	return nil
}

func (m mockResonseWriter) TsigTimersOnly(bool) {}

func (m mockResonseWriter) Hijack() {}
