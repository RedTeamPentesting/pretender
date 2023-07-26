package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	dnsPort = 53 // default DNS port

	// DefaultTTL is the time to live specified in replies to name resolution
	// queries of any type.
	dnsDefaultTTL = 60 * time.Second

	// NetBIOS name resolution messages have the type set to 32 which means
	// NIMLOC in the DNS spec. In this case we don't expect actual NIMLOC
	// messages, so we assume type 32 messages to be NetBIOS requests.
	typeNetBios = dns.TypeNIMLOC
)

// HandlerType specifies the type of name resolution query that is currently being handled.
type HandlerType string

//nolint:revive
var (
	HandlerTypeInvalid HandlerType = ""
	HandlerTypeDNS     HandlerType = "DNS"
	HandlerTypeLLMNR   HandlerType = "LLMNR"
	HandlerTypeMDNS    HandlerType = "mDNS"
	HandlerTypeNetBIOS HandlerType = "NetBIOS"
)

func createDNSReplyFromRequest(
	rw dns.ResponseWriter, request *dns.Msg, logger *Logger,
	config Config, handlerType HandlerType, delegateQuestion delegateQuestionFunc,
) *dns.Msg {
	reply := &dns.Msg{}
	reply.SetReply(request)
	reply.Authoritative = true // this has to be set for Windows to accept NetBIOS queries

	peer, err := toIP(rw.RemoteAddr())
	if err != nil {
		logger.Errorf(err.Error())

		return nil
	}

	var peerHostnames []string
	if logger != nil && logger.HostInfoCache != nil {
		peerHostnames = logger.HostInfoCache.Hostnames(peer)
	}

	allQuestions := make([]string, 0, len(request.Question))

	for _, q := range request.Question {
		name := normalizedNameFromQuery(q, handlerType)
		allQuestions = append(allQuestions, fmt.Sprintf("%q (%s)", name, queryType(q, request.Opcode)))

		shouldRespond, reason := shouldRespondToNameResolutionQuery(config, name, q.Qtype, peer, peerHostnames)
		if !shouldRespond {
			answers := handleIgnored(logger, q, name, queryType(q, request.Opcode), peer, reason, handlerType, delegateQuestion)
			reply.Answer = append(reply.Answer, answers...)

			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			reply.Answer = append(reply.Answer, rr(config.RelayIPv4, q.Name, config.TTL))
		case dns.TypeAAAA:
			reply.Answer = append(reply.Answer, rr(config.RelayIPv6, q.Name, config.TTL))
		case dns.TypeSOA:
			switch {
			case config.SOAHostname == "":
				logger.Errorf("SOA query from %s is not ignored but no SOA hostname was configured", peer)

				continue
			case request.Opcode == dns.OpcodeUpdate:
				// Refuse dynamic update to trigger authentication in TKEY query over TCP (not handled by pretender)
				reply.Rcode = dns.RcodeRefused
				reply.Ns = request.Ns
				reply.Answer = nil

				logger.RefuseDynamicUpdate(name, queryType(q, request.Opcode), peer)

				return reply // no need to react the other questions
			default:
				// Tell the client that a server with the hostname `SOAHostname`
				// is authoritative for the requested zone. And, btw: WE pretend
				// to be the host named `SOAHostname`.
				soaHostname := dns.Fqdn(config.SOAHostname)

				reply.Answer = append(reply.Answer, &dns.SOA{
					Hdr:  rrHeader(q.Name, dns.TypeSOA, config.TTL),
					Ns:   soaHostname,
					Mbox: "pretender.invalid.",
				})

				reply.Ns = append(reply.Ns, &dns.NS{
					Hdr: rrHeader(q.Name, dns.TypeNS, config.TTL),
					Ns:  soaHostname,
				})

				if config.RelayIPv4 != nil {
					reply.Extra = append(reply.Extra, rr(config.RelayIPv4, soaHostname, config.TTL))
				}

				if config.RelayIPv6 != nil {
					reply.Extra = append(reply.Extra, rr(config.RelayIPv6, soaHostname, config.TTL))
				}
			}
		case dns.TypeANY:
			if config.RelayIPv4 != nil {
				reply.Answer = append(reply.Answer, rr(config.RelayIPv4, q.Name, config.TTL))
			}

			if config.RelayIPv6 != nil {
				reply.Answer = append(reply.Answer, rr(config.RelayIPv6, q.Name, config.TTL))
			}
		case typeNetBios:
			reply.CheckingDisabled = false
			reply.Question = nil
			reply.Answer = append(reply.Answer, &dns.NIMLOC{
				Hdr:     rrHeader(q.Name, dns.TypeNIMLOC, config.TTL),
				Locator: encodeNetBIOSLocator(config.RelayIPv4.To4()),
			})
		default:
			answers := handleIgnored(logger, q, name, queryType(q, request.Opcode), peer, IgnoreReasonQueryTypeUnhandled,
				handlerType, delegateQuestion)
			reply.Answer = append(reply.Answer, answers...)

			continue
		}

		logger.Query(name, queryType(q, request.Opcode), peer)
	}

	// don't send a reply at all if we don't actually spoof anything
	if len(reply.Answer) == 0 && len(reply.Ns) == 0 && len(reply.Extra) == 0 &&
		(handlerType != HandlerTypeDNS || config.DontSendEmptyReplies) {
		logger.Debugf("ignoring query for %s from %s because no answers were configured",
			strings.Join(allQuestions, ", "), rw.RemoteAddr().String())

		return nil
	}

	return reply
}

func handleIgnored(
	logger *Logger, rawQuestion dns.Question, name string, queryType string, peer net.IP, reason string,
	handlerType HandlerType, delegateQuestion delegateQuestionFunc,
) []dns.RR {
	switch {
	case handlerType == HandlerTypeDNS && delegateQuestion != nil:
		rr, err := delegateQuestion(rawQuestion)
		if err != nil {
			logger.Errorf("cannot delegate %s query for %q from %s: %v", queryType, rawQuestion.Name, peer, err)
		}

		logger.IgnoreDNSWithDelegatedReply(name, queryType, peer, reason)

		return rr
	case reason == IgnoreReasonQueryTypeUnhandled:
		logger.Debugf("%s query for name %s from %s is unhandled", queryType, name, peer)
	default:
		logger.IgnoreNameResolutionQuery(name, queryType, peer, reason)
	}

	return nil
}

func rr(ip net.IP, name string, ttl time.Duration) dns.RR { //nolint:ireturn
	if ip.To4() == nil {
		return &dns.AAAA{Hdr: rrHeader(name, dns.TypeAAAA, ttl), AAAA: ip}
	}

	return &dns.A{Hdr: rrHeader(name, dns.TypeA, ttl), A: ip}
}

func rrHeader(name string, rtype uint16, ttl time.Duration) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rtype, Class: dns.ClassINET, Ttl: uint32(ttl.Seconds())}
}

func toIP(addr net.Addr) (net.IP, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP, nil
	case *net.UDPAddr:
		return a.IP, nil
	default:
		return nil, fmt.Errorf("cannot extract IP from %T", addr)
	}
}

func normalizedNameFromQuery(q dns.Question, hType HandlerType) string {
	if q.Qtype == typeNetBios {
		return decodeNetBIOSHostname(q.Name)
	}

	name := normalizedName(q.Name, hType)

	if name == "" {
		return q.Name
	}

	return name
}

func normalizedName(host string, hType HandlerType) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if hType == HandlerTypeMDNS {
		return strings.TrimSuffix(host, ".local")
	}

	return host
}

func queryType(q dns.Question, opcode int) string {
	if q.Qtype == typeNetBios {
		return decodeNetBIOSSuffix(q.Name)
	}

	typeStr := dnsQueryType(q.Qtype)

	switch opcode {
	case dns.OpcodeStatus:
		return typeStr + " Status"
	case dns.OpcodeNotify:
		return typeStr + " Notify"
	case dns.OpcodeUpdate:
		return typeStr + " Dynamic Update"
	default:
		return typeStr
	}
}

func dnsQueryType(qtype uint16) string {
	return dns.Type(qtype).String()
}

// DNSHandler creates a dns.HandlerFunc based on the logic in
// createReplyFromRequest.
func DNSHandler(logger *Logger, config Config) dns.HandlerFunc {
	var delegateQuestion delegateQuestionFunc

	if config.DelegateIgnoredTo != "" {
		delegateQuestion = delegateToDNSServer(config.DelegateIgnoredTo, config.DNSTimeout)
	}

	return func(rw dns.ResponseWriter, request *dns.Msg) {
		reply := createDNSReplyFromRequest(rw, request, logger, config, HandlerTypeDNS, delegateQuestion)
		if reply == nil {
			_ = rw.Close() // early abort for TCP connections

			return
		}

		err := rw.WriteMsg(reply)
		if err != nil {
			logger.Errorf("writing reply: %v", err)
		}
	}
}

// UDPConnDNSHandler handles requests by creating a response using
// createReplyFromRequest and sends it directly using the underlying UDP
// connection on which the server operates.
func UDPConnDNSHandler(conn net.PacketConn, logger *Logger, config Config, handlerType HandlerType) dns.HandlerFunc {
	return func(rw dns.ResponseWriter, request *dns.Msg) {
		reply := createDNSReplyFromRequest(rw, request, logger, config, handlerType, nil)
		if reply == nil {
			return
		}

		buf, err := reply.Pack()
		if err != nil {
			logger.Errorf("pack message: %v", err)

			return
		}

		_, err = conn.WriteTo(buf, rw.RemoteAddr())
		if err != nil {
			logger.Errorf("write dns reply: %v", err)

			return
		}
	}
}

// RunDNSResponder starts a TCP and a UDP DNS server.
func RunDNSResponder(ctx context.Context, logger *Logger, config Config) error {
	errGroup, ctx := errgroup.WithContext(ctx)

	ipv6Addr := net.IPAddr{IP: config.LocalIPv6, Zone: config.Interface.Name}
	fullAddr := net.JoinHostPort(ipv6Addr.String(), strconv.Itoa(dnsPort))

	errGroup.Go(func() error {
		logger.Infof("listening via UDP on %s", fullAddr)

		return runDNSServerWithContext(ctx, &dns.Server{
			Addr:          fullAddr,
			Net:           "udp6",
			Handler:       DNSHandler(logger, config),
			MsgAcceptFunc: acceptAllQueries,
		})
	})

	errGroup.Go(func() error {
		logger.Infof("listening via TCP on %s", fullAddr)

		return runDNSServerWithContext(ctx, &dns.Server{
			Addr:          fullAddr,
			Net:           "tcp6",
			Handler:       DNSHandler(logger, config),
			MsgAcceptFunc: acceptAllQueries,
		})
	})

	// listen on IPv4 port only if we expect to receive a dynamic update to the
	// relay IPv4 address following an SOA query
	if config.SOAHostname != "" && hasSpecificIPv4Address(config.Interface, config.RelayIPv4) {
		fullAddr := net.JoinHostPort(config.RelayIPv4.String(), strconv.Itoa(dnsPort))

		errGroup.Go(func() error {
			logger.Infof("listening via TCP on %s", fullAddr)

			return runDNSServerWithContext(ctx, &dns.Server{
				Addr:          fullAddr,
				Net:           "udp4",
				Handler:       DNSHandler(logger, config),
				MsgAcceptFunc: acceptAllQueries,
			})
		})
	}

	return errGroup.Wait()
}

func acceptAllQueries(dh dns.Header) dns.MsgAcceptAction {
	queryReplyBit := uint16(1 << 15) //nolint:gomnd

	if isReply := dh.Bits&queryReplyBit != 0; isReply {
		return dns.MsgIgnore
	}

	return dns.MsgAccept
}

func runDNSServerWithContext(ctx context.Context, server *dns.Server) error {
	go func() {
		<-ctx.Done()

		_ = server.Shutdown()
	}()

	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("activate and serve: %w", err)
	}

	return nil
}

// RunDNSHandlerOnUDPConnection runs the DNS handler on an arbitrary UDP
// connection, such that the DNS handling logic can be used for LLMNR, mDNS and
// NetBIOS name resolution.
func RunDNSHandlerOnUDPConnection(
	ctx context.Context, conn net.PacketConn, logger *Logger, config Config, handlerType HandlerType,
) error {
	server := &dns.Server{
		PacketConn: conn,
		Handler:    UDPConnDNSHandler(conn, logger, config, handlerType),
	}

	go func() {
		<-ctx.Done()

		_ = server.Shutdown()
	}()

	err := server.ActivateAndServe()
	if err != nil {
		return fmt.Errorf("activate and serve: %w", err)
	}

	return nil
}

func hasSpecificIPv4Address(iface *net.Interface, ip net.IP) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ifIP, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ifIP.IP.Equal(ip) {
			return true
		}
	}

	return false
}

type delegateQuestionFunc func(dns.Question) ([]dns.RR, error)

func delegateToDNSServer(dnsServer string, timeout time.Duration) delegateQuestionFunc {
	return func(q dns.Question) ([]dns.RR, error) {
		c := &dns.Client{
			Timeout: timeout,
		}

		if q.Qtype == dns.TypeANY || q.Qtype == dns.TypeTXT {
			c.Net = "tcp"
		}

		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = []dns.Question{q}

		reply, _, err := c.Exchange(m1, dnsServer)
		if err != nil {
			return nil, fmt.Errorf("lookup %q (%s): %w", q.Name, dnsQueryType(q.Qtype), err)
		}

		return reply.Answer, nil
	}
}
