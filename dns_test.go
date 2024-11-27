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
	testReply(t, "testdata/dns_request.bin", "testdata/dns_reply.bin")
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
		reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeDNS, nil)
		if reply == nil {
			t.Fatalf("config %d: no message was created", i)

			return // calm down staticcheck linter
		}

		expectedNumberOfAnswers := 0

		if cfg.RelayIPv4 != nil {
			expectedNumberOfAnswers++

			aAnswer, ok := getAnswerByType(t, reply.Answer, dns.TypeA).(*dns.A)
			if !ok {
				t.Fatalf("config %d: unexpected type for A answer", i)
			}

			assertRRHeader(t, aAnswer.Hdr, "host", dns.TypeA, cfg.TTL)

			if !aAnswer.A.Equal(relayIPv4) {
				t.Fatalf("config %d: abnswer contains A address %s instead of %s",
					i, aAnswer.A, relayIPv4)
			}
		}

		if cfg.RelayIPv6 != nil {
			expectedNumberOfAnswers++

			aaaaAnswer, ok := getAnswerByType(t, reply.Answer, dns.TypeAAAA).(*dns.AAAA)
			if !ok {
				t.Fatalf("config %d: unexpected type for A answer", i)
			}

			assertRRHeader(t, aaaaAnswer.Hdr, "host", dns.TypeAAAA, cfg.TTL)

			if !aaaaAnswer.AAAA.Equal(relayIPv6) {
				t.Fatalf("config %d: abnswer contains AAAA address %s instead of %s",
					i, aaaaAnswer.AAAA, relayIPv6)
			}
		}

		if len(reply.Answer) != expectedNumberOfAnswers {
			t.Fatalf("config %d: unexpected number of answers: %d instead of %d",
				i, len(reply.Answer), expectedNumberOfAnswers)
		}
	}
}

func TestDNSSOA(t *testing.T) {
	soa := &dns.Msg{}
	soa.SetQuestion("host", dns.TypeSOA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	relayIPv6 := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{RelayIPv4: relayIPv4, RelayIPv6: relayIPv6, TTL: 60 * time.Second, DontSendEmptyReplies: true}

	// don't respond to SOA when no SOA hostname is configured
	noReply := createDNSReplyFromRequest(mockRW, soa, nil, cfg, HandlerTypeDNS, nil)
	if noReply != nil {
		t.Fatalf("SOA rely was created without configuring SOA hostname")
	}

	cfg.SOAHostname = "hostname"

	reply := createDNSReplyFromRequest(mockRW, soa, nil, cfg, HandlerTypeDNS, nil)
	if reply == nil {
		t.Fatalf("no SOA reply was created")
	}

	soaAnswer, ok := getAnswerByType(t, reply.Answer, dns.TypeSOA).(*dns.SOA)
	if !ok {
		t.Fatalf("SOA answer has unexpected type")
	}

	assertRRHeader(t, soaAnswer.Hdr, "host", dns.TypeSOA, cfg.TTL)

	if soaAnswer.Ns != dns.Fqdn(cfg.SOAHostname) {
		t.Fatalf("unexpected SOA answer hostname: %q instead of %q",
			soaAnswer.Ns, dns.Fqdn(cfg.SOAHostname))
	}

	soaNS, ok := getAnswerByType(t, reply.Ns, dns.TypeNS).(*dns.NS)
	if !ok {
		t.Fatalf("SOA NS has unexpected type")
	}

	assertRRHeader(t, soaNS.Hdr, "host", dns.TypeNS, cfg.TTL)

	if soaNS.Ns != dns.Fqdn(cfg.SOAHostname) {
		t.Fatalf("unexpected SOA NS hostname: %q instead of %q",
			soaNS.Ns, dns.Fqdn(cfg.SOAHostname))
	}

	soaA, ok := getAnswerByType(t, reply.Extra, dns.TypeA).(*dns.A)
	if !ok {
		t.Fatalf("SOA A record has unexpected type")
	}

	assertRRHeader(t, soaA.Hdr, dns.Fqdn(cfg.SOAHostname), dns.TypeA, cfg.TTL)

	if !soaA.A.Equal(relayIPv4) {
		t.Fatalf("SOA extra A record contains address %s instead of %s",
			soaA.A, relayIPv4)
	}

	soaAAAA, ok := getAnswerByType(t, reply.Extra, dns.TypeAAAA).(*dns.AAAA)
	if !ok {
		t.Fatalf("SOA AAAA record has unexpected type")
	}

	assertRRHeader(t, soaAAAA.Hdr, dns.Fqdn(cfg.SOAHostname), dns.TypeAAAA, cfg.TTL)

	if !soaAAAA.AAAA.Equal(relayIPv6) {
		t.Fatalf("SOA extra AAAA record contains address %s instead of %s",
			soaAAAA.AAAA, relayIPv6)
	}
}

func TestDNSSOADynamicUpdate(t *testing.T) {
	soa := &dns.Msg{}
	soa.SetQuestion("host", dns.TypeSOA)
	soa.Opcode = dns.OpcodeUpdate

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	relayIPv6 := mustParseIP(t, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4:   relayIPv4,
		RelayIPv6:   relayIPv6,
		TTL:         60 * time.Second,
		SOAHostname: "hostname",
	}

	reply := createDNSReplyFromRequest(mockRW, soa, nil, cfg, HandlerTypeDNS, nil)
	if reply == nil {
		t.Fatalf("no SOA reply was created")
	}

	if reply.Rcode != dns.RcodeRefused {
		t.Fatalf("SOA dynamic update was not refused")
	}
}

func TestIgnored(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4: relayIPv4,
		SpoofFor:  []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS, nil)
	if reply == nil {
		t.Fatalf("no reply")
	}

	if len(reply.Answer) != 0 {
		t.Fatalf("reply of ignored request contains %d answers instead of 0", len(reply.Answer))
	}
}

func TestIgnoredNoReply(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4:            relayIPv4,
		SpoofFor:             []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
		DontSendEmptyReplies: true,
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS, nil)
	if reply != nil {
		t.Fatalf("reply is not nil")
	}
}

func TestIgnoredNoReplyNonDNS(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4: relayIPv4,
		SpoofFor:  []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeLLMNR, nil)
	if reply != nil {
		t.Fatalf("reply is not nil")
	}
}

func TestDNSDelegation(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	delegatedResponseIP := mustParseIP(t, "1.2.3.4")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4: relayIPv4,
		SpoofFor:  []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS,
		func(q dns.Question, _ string) ([]dns.RR, error) {
			if q.Qtype == dns.TypeA && q.Name == "host" {
				return []dns.RR{&dns.A{Hdr: rrHeader(q.Name, dns.TypeA, 1*time.Second), A: delegatedResponseIP}}, nil
			}

			return nil, nil
		})
	if reply == nil {
		t.Fatalf("no delegated reply")
	}

	if len(reply.Answer) == 0 {
		t.Fatalf("no answer in delegated reply")
	}

	aRecord, ok := reply.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is not an A record but a %T", reply.Answer[0])
	}

	if !aRecord.A.Equal(delegatedResponseIP) {
		t.Fatalf("answer is %s instead of %s", aRecord.A, delegatedResponseIP)
	}
}

func TestUnhandledQuery(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypePTR)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4: relayIPv4,
		SpoofFor:  []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS, nil)
	if reply == nil {
		t.Fatalf("reply is nil")
	}

	if len(reply.Answer) != 0 {
		t.Fatalf("reply for unhandled query returned %d answers instead of 0", len(reply.Answer))
	}
}

func TestDelegatedUnhandledQuery(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypePTR)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	delegatedPTR := "foo"
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{
		RelayIPv4: relayIPv4,
		SpoofFor:  []*hostMatcher{newHostMatcher("10.0.0.99", defaultLookupTimeout)},
	}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS,
		func(q dns.Question, _ string) ([]dns.RR, error) {
			if q.Qtype == dns.TypePTR && q.Name == "host" {
				return []dns.RR{&dns.PTR{Hdr: rrHeader(q.Name, dns.TypePTR, 1*time.Second), Ptr: delegatedPTR}}, nil
			}

			return nil, nil
		})
	if reply == nil {
		t.Fatalf("no delegated reply")
	}

	if len(reply.Answer) == 0 {
		t.Fatalf("no answer in delegated reply")
	}

	ptrRecord, ok := reply.Answer[0].(*dns.PTR)
	if !ok {
		t.Fatalf("answer is not an A record but a %T", reply.Answer[0])
	}

	if ptrRecord.Ptr != delegatedPTR {
		t.Fatalf("answer is %s instead of %s", ptrRecord.Ptr, delegatedPTR)
	}
}

func TestDelegatedQueryUDP(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeANY)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{RelayIPv4: relayIPv4}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS,
		func(q dns.Question, net string) ([]dns.RR, error) {
			if net != "udp" {
				t.Fatalf("UDP query was delegated via %q", net)
			}

			return []dns.RR{&dns.ANY{Hdr: rrHeader(q.Name, dns.TypeANY, 1*time.Second)}}, nil
		})
	if reply == nil {
		t.Fatalf("no delegated reply")
	}
}

func TestDelegatedQueryTCP(t *testing.T) {
	aQuery := &dns.Msg{}
	aQuery.SetQuestion("host", dns.TypeA)

	relayIPv4 := mustParseIP(t, "10.0.0.2")
	mockRW := mockResonseWriter{Remote: &net.TCPAddr{IP: mustParseIP(t, "10.0.0.1")}}

	cfg := Config{RelayIPv4: relayIPv4}

	reply := createDNSReplyFromRequest(mockRW, aQuery, nil, cfg, HandlerTypeDNS,
		func(q dns.Question, net string) ([]dns.RR, error) {
			if net != "tcp" {
				t.Fatalf("TCP query was delegated via %q", net)
			}

			return []dns.RR{&dns.A{Hdr: rrHeader(q.Name, dns.TypeA, 1*time.Second), A: relayIPv4}}, nil
		})
	if reply == nil {
		t.Fatalf("no delegated reply")
	}
}

func testReply(tb testing.TB, requestFileName string, replyFileName string) {
	tb.Helper()

	relayIPv4 := mustParseIP(tb, "10.0.0.2")
	relayIPv6 := mustParseIP(tb, "fe80::1")
	mockRW := mockResonseWriter{Remote: &net.UDPAddr{IP: mustParseIP(tb, "10.0.0.1")}}
	request := readNameServiceMessage(tb, requestFileName)
	expectedReply := readFile(tb, replyFileName)
	cfg := Config{RelayIPv4: relayIPv4, RelayIPv6: relayIPv6, TTL: 60 * time.Second}

	reply := createDNSReplyFromRequest(mockRW, request, nil, cfg, HandlerTypeDNS, nil)
	if reply == nil {
		tb.Fatalf("no message was created")

		return // calm down staticcheck linter
	}

	if len(reply.Answer) == 0 {
		tb.Fatalf("reply contains no answers")
	}

	for _, answer := range reply.Answer {
		switch a := answer.(type) {
		case *dns.A:
			if !a.A.Equal(relayIPv4) {
				tb.Fatalf("reply contains A address %s instead of %s", a.A, relayIPv4)
			}

			if a.Hdr.Rrtype != dns.TypeA {
				tb.Fatalf("unexpected type: got %s instead of %s", dnsQueryType(a.Hdr.Rrtype), dnsQueryType(dns.TypeA))
			}
		case *dns.AAAA:
			if !a.AAAA.Equal(relayIPv6) {
				tb.Fatalf("reply contains AAAA address %s instead of %s", a.AAAA, relayIPv6)
			}

			if a.Hdr.Rrtype != dns.TypeAAAA {
				tb.Fatalf("unexpected type: got %s instead of %s", dnsQueryType(a.Hdr.Rrtype), dnsQueryType(dns.TypeAAAA))
			}
		default:
			tb.Fatalf("unexpected reply type %T", answer)
		}

		answerHeader := answer.Header()

		if answerHeader.Ttl != uint32(cfg.TTL.Seconds()) {
			tb.Fatalf("unexpected TTL: got %ds instead of %ds", answerHeader.Ttl, uint32(cfg.TTL.Seconds()))
		}

		if answerHeader.Name != request.Question[0].Name {
			tb.Fatalf("%q was echoed instead of question name %q", answerHeader.Name, reply.Question[0].Name)
		}

		if answerHeader.Class != dns.ClassINET {
			tb.Fatalf("unexpected class: got %d instead of %d", answerHeader.Class, dns.ClassINET)
		}
	}

	replyBuffer, err := reply.Pack()
	if err != nil {
		tb.Fatalf("pack reply: %v", err)
	}

	if !bytes.Equal(replyBuffer, expectedReply) {
		tb.Fatalf("reply bytes do not match")
	}
}

func getAnswerByType(tb testing.TB, answers []dns.RR, answerType uint16) dns.RR { //nolint:ireturn
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

	content, err := os.ReadFile(fileName) //nolint:gosec
	if err != nil {
		tb.Fatalf("read file: %v", err)
	}

	return content
}

func assertRRHeader(tb testing.TB, hdr dns.RR_Header, name string, rtype uint16, ttl time.Duration) {
	tb.Helper()

	if hdr.Name != name {
		tb.Fatalf("unexpected name in header: %q instead of %q", hdr.Name, name)
	}

	if hdr.Rrtype != rtype {
		tb.Fatalf("unexpected type in header: %d instead of %d", hdr.Rrtype, rtype)
	}

	if hdr.Class != dns.ClassINET {
		tb.Fatalf("unexpected class in header: %d instead of %d", hdr.Class, dns.ClassINET)
	}

	if hdr.Ttl != uint32(ttl.Seconds()) {
		tb.Fatalf("unexpected TTL in header: %ds instead of %s", hdr.Ttl, ttl)
	}
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
