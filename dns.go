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

	// DefaultTTL is the time to live specified in responses to name resolution
	// queries of any type.
	dnsDefaultTTL = 60 * time.Second

	// NetBIOS name resolution messages have the type set to 32 which means
	// NIMLOC in the DNS spec. In this case we don't expect actual NIMLOC
	// messages, so we assume type 32 messages to be NetBIOS requests.
	typeNetBios = dns.TypeNIMLOC
)

// nolint:cyclop
func createDNSReplyFromRequest(rw dns.ResponseWriter, request *dns.Msg, logger *Logger, config Config) *dns.Msg {
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

	for _, q := range request.Question {
		name := normalizedNameFromQuery(q)

		shouldRespond, reason := shouldRespondToNameResolutionQuery(config, name, q.Qtype, peer, peerHostnames)
		if !shouldRespond {
			logger.IgnoreDNS(name, queryType(q, request.Opcode), peer, reason)

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
				logger.IgnoreDNS(name, queryType(q, request.Opcode), peer, "no SOA hostname configured")

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
			logger.Debugf("%s query for name %s from %s is unhandled",
				dns.Type(q.Qtype).String(), name, rw.RemoteAddr().String())

			continue
		}

		logger.Query(name, queryType(q, request.Opcode), peer)
	}

	// don't send a reply at all if we don't actually spoof anything
	if len(reply.Answer) == 0 && len(reply.Ns) == 0 && len(reply.Extra) == 0 {
		logger.Debugf("ignoring query from %s because no answers were configured", rw.RemoteAddr().String())

		return nil
	}

	return reply
}

// nolint:ireturn
func rr(ip net.IP, name string, ttl time.Duration) dns.RR {
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

func normalizedNameFromQuery(q dns.Question) string {
	if q.Qtype == typeNetBios {
		return decodeNetBIOSHostname(q.Name)
	}

	name := normalizedName(q.Name)

	if name == "" {
		return q.Name
	}

	return name
}

func normalizedName(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
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

// DNSHandler creates a dns.HandlerFunc based on the logic in createResponseFromRequest.
func DNSHandler(logger *Logger, config Config) dns.HandlerFunc {
	return func(rw dns.ResponseWriter, request *dns.Msg) {
		reply := createDNSReplyFromRequest(rw, request, logger, config)
		if reply == nil {
			_ = rw.Close() // early abort for TCP connections

			return
		}

		err := rw.WriteMsg(reply)
		if err != nil {
			logger.Errorf("writing response: %v", err)
		}
	}
}

// UDPConnDNSHandler handles requests by creating a response using
// createResponseFromRequest and sends it directly using the underlying UDP
// connection on which the server operates.
func UDPConnDNSHandler(conn net.PacketConn, logger *Logger, config Config) dns.HandlerFunc {
	return func(rw dns.ResponseWriter, request *dns.Msg) {
		reply := createDNSReplyFromRequest(rw, request, logger, config)
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
			logger.Errorf("write dns response: %v", err)

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
	queryResponseBit := uint16(1 << 15) // nolint:gomnd

	if isResponse := dh.Bits&queryResponseBit != 0; isResponse {
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
func RunDNSHandlerOnUDPConnection(ctx context.Context, conn net.PacketConn, logger *Logger, config Config) error {
	server := &dns.Server{
		PacketConn: conn,
		Handler:    UDPConnDNSHandler(conn, logger, config),
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
