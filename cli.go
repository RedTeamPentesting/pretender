package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

var stdErr = os.Stderr // this is used to make stderr redirectable without side effects

// Config holds the configuration.
type Config struct {
	RelayIPv4      net.IP
	RelayIPv6      net.IP
	SOAHostname    string
	Interface      *net.Interface
	TTL            time.Duration
	LeaseLifetime  time.Duration
	RouterLifetime time.Duration
	LocalIPv6      net.IP
	RAPeriod       time.Duration
	DNSTimeout     time.Duration

	NoDHCPv6DNSTakeover   bool
	NoDHCPv6              bool
	NoDNS                 bool
	NoRA                  bool
	NoMDNS                bool
	NoNetBIOS             bool
	NoLLMNR               bool
	NoLocalNameResolution bool
	NoIPv6LNR             bool

	Spoof                []string
	DontSpoof            []string
	SpoofFor             []*hostMatcher
	DontSpoofFor         []*hostMatcher
	SpoofTypes           *spoofTypes
	IgnoreDHCPv6NoFQDN   bool
	DelegateIgnoredTo    string
	DontSendEmptyReplies bool
	DryMode              bool
	DryWithDHCPv6        bool

	StopAfter      time.Duration
	Verbose        bool
	NoColor        bool
	NoTimestamps   bool
	LogFileName    string
	NoHostInfo     bool
	HideIgnored    bool
	RedirectStderr bool
	ListInterfaces bool

	spoofFor     []string
	dontSpoofFor []string
	spoofTypes   []string
}

// PrintSummary prints a summary of some important configuration parameters.
//
//nolint:forbidigo
func (c Config) PrintSummary() { //nolint:cyclop
	fmt.Printf("Listening on interface: %s\n", c.Interface.Name)

	if c.LogFileName != "" {
		fmt.Printf("Logging to file: %s\n", c.LogFileName)
	}

	if c.RelayIPv4 != nil {
		fmt.Printf("IPv4 relayed to: %s\n", c.RelayIPv4)
	}

	if c.RelayIPv6 != nil {
		fmt.Printf("IPv6 relayed to: %s\n", c.RelayIPv6)
	}

	if c.SOAHostname != "" {
		fmt.Printf("SOA Requests answered with: %s\n", c.SOAHostname)
	}

	switch {
	case c.DryMode:
		var raNotice string

		if !c.NoRA && !c.NoDHCPv6DNSTakeover && !c.NoDHCPv6 {
			raNotice = " (RA is still enabled)"
		}

		fmt.Println("Dry Mode: DHCPv6 and name resolution queries will not be answered" + raNotice)
	default:
		if len(c.Spoof) != 0 {
			fmt.Println("Answering queries for: " + joinDomains(c.Spoof))
		}

		if len(c.DontSpoof) != 0 {
			fmt.Println("Ignoring queries for: " + joinDomains(c.DontSpoof))
		}

		if len(c.SpoofFor) != 0 {
			fmt.Println("Answering queries from: " + joinHosts(c.SpoofFor, ", "))
		}

		if len(c.DontSpoofFor) != 0 {
			fmt.Println("Ignoring queries from: " + joinHosts(c.DontSpoofFor, ", "))
		}

		if len(c.spoofTypes) != 0 {
			fmt.Println("Answering only queries of type: " + strings.Join(toUpper(c.spoofTypes), ", "))
		}
	}

	if c.DelegateIgnoredTo != "" {
		fmt.Println("Ignored DNS queries are delegated to DNS server:", c.DelegateIgnoredTo)
	}

	if c.StopAfter > 0 {
		fmt.Printf("Pretender will automatically terminate after: %s\n", formatStopAfter(c.StopAfter))
	}

	fmt.Println()
}

//nolint:forbidigo,cyclop,maintidx
func configFromCLI() (config Config, logger *Logger, err error) {
	var (
		interfaceName string
		printVersion  bool
	)

	pflag.StringVarP(&interfaceName, "interface", "i", defaultInterface,
		"Interface to bind on, supports auto-detection by IPv4 or IPv6")
	pflag.IPVarP(&config.RelayIPv4, "ipv4", "4", defaultRelayIPv4,
		"Relay IPv4 address with which queries are answered, supports\nauto-detection by interface or IPv6")
	pflag.IPVarP(&config.RelayIPv6, "ipv6", "6", defaultRelayIPv6,
		"Relay IPv6 address with which queries are answered, supports\nauto-detection by interface or IPv4")
	pflag.StringVar(&config.SOAHostname, "soa-hostname", defaultSOAHostname,
		"Hostname for the SOA record (useful for Kerberos relaying)")

	pflag.BoolVar(&config.NoDHCPv6DNSTakeover, "no-dhcp-dns", defaultNoDHCPv6DNSTakeover,
		"Disable DHCPv6 DNS takeover attack (DHCPv6 and DNS)")
	pflag.BoolVar(&config.NoDHCPv6, "no-dhcp", defaultNoDHCPv6, "Disable DHCPv6 spoofing")
	pflag.BoolVar(&config.NoDNS, "no-dns", defaultNoDNS, "Disable DNS spoofing")
	pflag.BoolVar(&config.NoRA, "no-ra", defaultNoRA, "Disable router advertisements")
	pflag.BoolVar(&config.NoMDNS, "no-mdns", defaultNoMDNS, "Disable mDNS spoofing")
	pflag.BoolVar(&config.NoNetBIOS, "no-netbios", defaultNoNetBIOS, "Disable NetBIOS-NS spoofing")
	pflag.BoolVar(&config.NoLLMNR, "no-llmnr", defaultNoLLMNR, "Disable LLMNR spoofing")
	pflag.BoolVar(&config.NoLocalNameResolution, "no-lnr", defaultNoLocalNameResolution,
		"Disable local name resolution spoofing (mDNS, LLMNR, NetBIOS-NS)")
	pflag.BoolVar(&config.NoIPv6LNR, "no-ipv6-lnr", defaultNoIPv6LNR,
		"Disable mDNS and LLMNR via IPv6 (useful with allowlist or blocklist)")

	pflag.StringSliceVar(&config.Spoof, "spoof", defaultSpoof,
		"Only spoof these domains, includes subdomain if it starts with\na dot, a single dot "+
			"matches local hostnames (allowlist)")
	pflag.StringSliceVar(&config.DontSpoof, "dont-spoof", defaultDontSpoof,
		"Do not spoof these domains, includes subdomains if it starts\nwitha dot, a single dot "+
			"matches local hostnames (blocklist)")
	pflag.StringSliceVar(&config.spoofFor, "spoof-for", defaultSpoofFor,
		"Only spoof DHCPv6 and name resolution for these `hosts`, it can\ncontain IPs or hostnames "+
			"and subdomains are included when the hostname\nstarts with a dot (allowlist)")
	pflag.StringSliceVar(&config.dontSpoofFor, "dont-spoof-for", defaultDontSpoofFor,
		"Do not spoof DHCPv6 and name resolution for these `hosts`, it can\ncontain IPs or hostnames "+
			"and subdomains are included when the hostname\nstarts with a dot (blocklist)")
	pflag.StringSliceVar(&config.spoofTypes, "spoof-types", defaultSpoofTypes,
		"Only spoof these query `types` (A, AAA, ANY, SOA, all types are spoofed\nif it is empty)")
	pflag.BoolVar(&config.IgnoreDHCPv6NoFQDN, "ignore-nofqdn", defaultIgnoreDHCPv6NoFQDN,
		"Ignore DHCPv6 messages where the client did not include its\nFQDN (useful with allowlist or blocklists)")
	pflag.StringVar(&config.DelegateIgnoredTo, "delegate-ignored-to", defaultDelegateIgnoredTo,
		"Delegate ignored DNS queries to an upstream `DNS server`")
	pflag.BoolVar(&config.DontSendEmptyReplies, "dont-send-empty-replies", defaultDontSendEmptyReplies,
		"Don't reply at all to ignored DNS queries or failed delegated\nqueries instead of sending an empty reply")
	pflag.BoolVar(&config.DryMode, "dry", defaultDryMode,
		"Do not spoof name resolution at all, only log queries (does not disable\nRA but it"+
			" can be combined with --no-ra)")

	pflag.DurationVarP(&config.TTL, "ttl", "t", defaultTTL, "Time to live for name resolution responses")
	pflag.DurationVar(&config.LeaseLifetime, "lease-lifetime", defaultLeaseLifetime, "DHCPv6 IP lease lifetime")
	pflag.DurationVar(&config.RouterLifetime, "router-lifetime", defaultRARouterLifetime,
		"Router lifetime specified in router advertisements")
	pflag.DurationVar(&config.RAPeriod, "ra-period", defaultRAPeriod, "Time period between router advertisements")
	pflag.DurationVar(&config.DNSTimeout, "dns-timeout", defaultDNSTimeout,
		"Timeout for DNS queries performed by pretender")

	pflag.DurationVar(&config.StopAfter, "stop-after", defaultStopAfter, "Stop running after this duration")
	pflag.BoolVarP(&config.Verbose, "verbose", "v", defaultVerbose, "Print debug information")
	pflag.BoolVar(&config.NoColor, "no-color", defaultNoColor, "Disables output styling")
	pflag.BoolVar(&config.NoTimestamps, "no-timestamps", defaultNoTimestamps, "Disables timestamps in the output")
	pflag.StringVarP(&config.LogFileName, "log", "l", defaultLogFileName, "Log `file` name")
	pflag.BoolVar(&printVersion, "version", false, "Print version information")
	pflag.BoolVar(&config.NoHostInfo, "no-host-info", defaultNoHostInfo, "Do not gather host information")
	pflag.BoolVar(&config.HideIgnored, "hide-ignored", defaultHideIgnored, "Do not log ignored queries")
	pflag.BoolVar(&config.RedirectStderr, "redirect-stderr", defaultRedirectStderr, "Redirect stderr to stdout")
	pflag.BoolVar(&config.ListInterfaces, "interfaces", defaultListInterfaces,
		"List interfaces and their addresses (the other options have no effect,\nexcept for --no-color)")

	pflag.CommandLine.SortFlags = false

	pflag.Parse()

	if pflag.NArg() > 0 {
		fmt.Printf("%s does not take positional arguments, only the following flags\n\n", binaryName())
		pflag.PrintDefaults()

		os.Exit(1)
	}

	if config.RedirectStderr {
		stdErr = os.Stdout
	}

	if config.NoDNS && config.NoDHCPv6 {
		config.NoDHCPv6DNSTakeover = true
	}

	if config.NoMDNS && config.NoLLMNR && config.NoNetBIOS {
		config.NoLocalNameResolution = true
	}

	if config.NoLocalNameResolution {
		config.NoNetBIOS = true
		config.NoLLMNR = true
		config.NoMDNS = true
	}

	if printVersion {
		fmt.Println(longVersion())
	} else {
		fmt.Println(shortVersion())
	}

	if printVersion {
		os.Exit(0)
	}

	if config.ListInterfaces {
		err := listInterfaces(os.Stdout, config.NoColor)
		if err != nil {
			fmt.Fprintf(stdErr, "Error: %v", err)

			os.Exit(1)
		}

		os.Exit(0)
	}

	logger = NewLogger().WithPrefix("Setup")
	logger.Verbose = config.Verbose
	logger.NoColor = config.NoColor
	logger.PrintTimestamps = !config.NoTimestamps
	logger.HideIgnored = config.HideIgnored
	logger.NoHostInfo = config.NoHostInfo

	if logger.HostInfoCache != nil {
		logger.HostInfoCache.DNSTimeout = config.DNSTimeout
	}

	if config.LogFileName != "" {
		f, err := os.OpenFile(config.LogFileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return config, logger, fmt.Errorf("log file: %w", err)
		}

		logger.LogFile = f
	}

	if !config.NoColor {
		err := enableVirtualTerminalProcessing()
		if err != nil {
			config.NoColor = true
			logger.NoColor = true

			logger.Errorf("Warning: cannot enable virtual terminal processing: %v, disabling colored output", err)
			logger.Flush()
		}
	}

	config.Interface, err = chooseInterface(interfaceName, config.RelayIPv4, config.RelayIPv6)
	if err != nil {
		return config, logger, interfaceError{err}
	}

	var errIPv4, errIPv6 error

	config.RelayIPv4, errIPv4 = autoConfigureRelayIPv4(config.Interface, config.RelayIPv4, config.RelayIPv6)
	config.RelayIPv6, errIPv6 = autoConfigureRelayIPv6(config.Interface, config.RelayIPv4, config.RelayIPv6)

	if config.RelayIPv4 == nil && !config.NoNetBIOS {
		logger.Errorf("no relay IPv4 configured (required for NetBIOS-NS): %v", errIPv4)

		config.NoNetBIOS = true
	}

	if config.RelayIPv6 == nil && config.RelayIPv4 == nil {
		return config, logger, fmt.Errorf("no relay IP configured: %s and %s", errIPv4, errIPv6) //nolint:errorlint
	}

	config.LocalIPv6, err = getLinkLocalIPv6Address(config.Interface)
	if err != nil && !config.NoDHCPv6DNSTakeover {
		logger.Errorf("cannot detect link local IPv6 (required for DHCPv6 DNS takeover): %v", err)

		config.NoDHCPv6DNSTakeover = true
	}

	if config.DelegateIgnoredTo != "" {
		upstreamDNSAddr, err := asDNSServerAddress(config.DelegateIgnoredTo)
		if err != nil {
			return config, logger, fmt.Errorf("invalid upstream DNS address: %w", err)
		}

		config.DelegateIgnoredTo = upstreamDNSAddr
	}

	config.SpoofFor = asHostMatchers(config.spoofFor, config.DNSTimeout)
	config.DontSpoofFor = asHostMatchers(config.dontSpoofFor, config.DNSTimeout)

	config.SpoofTypes, err = parseSpoofTypes(config.spoofTypes)
	if err != nil {
		return config, logger, fmt.Errorf("parsing --spoof-types: %w", err)
	}

	config.PrintSummary()

	return config, logger, nil
}

func joinDomains(domains []string) string {
	processed := make([]string, 0, len(domains))

	for _, domain := range domains {
		switch {
		case domain == ".":
			processed = append(processed, "<local hostnames>")
		case strings.HasPrefix(domain, "."):
			processed = append(processed, "*"+strings.TrimRight(domain, "."))
		default:
			processed = append(processed, strings.TrimRight(domain, "."))
		}
	}

	return strings.Join(processed, ", ")
}

func joinHosts(hosts []*hostMatcher, sep string) string {
	hostStrings := make([]string, 0, len(hosts))

	for _, ip := range hosts {
		hostStrings = append(hostStrings, ip.String())
	}

	return strings.Join(hostStrings, sep)
}

func isLocalIP(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ifaceIP, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if net.IP.Equal(ifaceIP.IP, ip) {
				return true
			}
		}
	}

	return false
}

//nolint:cyclop
func chooseInterface(interfaceName string, ipv4, ipv6 net.IP) (*net.Interface, error) {
	if interfaceName != "" {
		return net.InterfaceByName(interfaceName)
	}

	var candidateByIPv4, candidateByIPv6 *net.Interface

	var err error

	if ipv4 != nil {
		if ipv4.To4() == nil {
			return nil, fmt.Errorf("expected IPv4 address but got IPv6 address %s", ipv4)
		}

		candidateByIPv4, err = getInterfaceByIP(ipv4)
		if err != nil {
			return nil, fmt.Errorf("choose interface by IP: %w", err)
		}
	}

	if ipv6 != nil {
		if ipv6.To4() != nil {
			return nil, fmt.Errorf("expected IPv6 address but got IPv6 address %s", ipv6)
		}

		candidateByIPv6, err = getInterfaceByIP(ipv6)
		if err != nil {
			return nil, fmt.Errorf("choose interface by IP: %w", err)
		}
	}

	if ipv4 == nil && ipv6 == nil {
		return nil, fmt.Errorf("interface cannot be automatically detected when no relay addresses are provided")
	}

	if candidateByIPv4 != nil && candidateByIPv6 == nil {
		return candidateByIPv4, nil
	}

	if candidateByIPv6 != nil && candidateByIPv4 == nil {
		return candidateByIPv6, nil
	}

	if candidateByIPv4 == nil && candidateByIPv6 == nil {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("listing interfaces: %w", err)
		}

		ifaces = withoutLoopback(ifaces)
		if len(ifaces) != 0 {
			return nil, fmt.Errorf("no possible candidates to determine interface")
		}

		return &ifaces[0], nil
	}

	if candidateByIPv4.Name != candidateByIPv6.Name {
		return nil, fmt.Errorf("cannot determine interface: conflict between %s (by IPv4) and %s (by IPv6)",
			candidateByIPv4.Name, candidateByIPv6.Name)
	}

	return candidateByIPv4, nil
}

func withoutLoopback(ifaces []net.Interface) []net.Interface {
	filtered := []net.Interface{}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			filtered = append(filtered, iface)
		}
	}

	return filtered
}

func getInterfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ifaceIP, ok := addr.(*net.IPNet)
			if !ok {
				return nil, fmt.Errorf("unexpected IP type: %T", addr)
			}

			if net.IP.Equal(ifaceIP.IP, ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("cannot find interface with IP %s", ip)
}

func autoConfigureRelayIPv4(iface *net.Interface, ipv4, ipv6 net.IP) (net.IP, error) {
	if ipv4 == nil {
		if ipv6 != nil && !isLocalIP(ipv6) {
			return nil, fmt.Errorf("IPv4 auto detection disabled when remote IPv6 relay is configured")
		}

		ip, err := detectLocalIPv4(iface)
		if err != nil {
			return nil, fmt.Errorf("cannot auto-detect IPv4: %w", err)
		}

		return ip, nil
	}

	if ipv4.To4() == nil {
		return nil, fmt.Errorf("expected IPv4 address but got IPv6 address %s", ipv4)
	}

	return ipv4, nil
}

func detectLocalIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("listing addresses of interface %q: %w", iface.Name, err)
	}

	candidates := []net.IP{}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("unexpected IP type: %T", addr)
		}

		if ip.IP.To4() == nil {
			continue
		}

		candidates = append(candidates, ip.IP)
	}

	if len(candidates) > 1 {
		return nil, fmt.Errorf("multiple possible IPv4 addresses on interface %q", iface.Name)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("interface %q has no IPv4 addresses", iface.Name)
	}

	return candidates[0], nil
}

func autoConfigureRelayIPv6(iface *net.Interface, ipv4, ipv6 net.IP) (net.IP, error) {
	if ipv6 == nil {
		if ipv4 != nil && !isLocalIP(ipv4) {
			return nil, fmt.Errorf("IPv4 auto detection disabled when remote IPv4 relay is configured")
		}

		ip, err := detectLocalIPv6(iface)
		if err != nil {
			return nil, fmt.Errorf("cannot auto-detect IPv6: %w", err)
		}

		return ip, nil
	}

	if ipv6.To4() != nil {
		return nil, fmt.Errorf("expected IPv6 address but got IPv4 address %s", ipv6)
	}

	return ipv6, nil
}

func detectLocalIPv6(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("listing addresses of interface %q: %w", iface.Name, err)
	}

	candidates := []net.IP{}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("unexpected IP type: %T", addr)
		}

		if ip.IP.To4() != nil || ip.IP.IsLinkLocalMulticast() {
			continue
		}

		candidates = append(candidates, ip.IP)
	}

	if len(candidates) > 1 {
		return nil, fmt.Errorf("multiple possible IPv6 addresses on interface %q", iface.Name)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("interface %q has no IPv6 addresses", iface.Name)
	}

	return candidates[0], nil
}

func getLinkLocalIPv6Address(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("gather addresses of interface %q: %w", iface.Name, err)
	}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("unexpected IP type: %T", addr)
		}

		if ip.IP.IsLinkLocalUnicast() {
			return ip.IP, nil
		}
	}

	return nil, fmt.Errorf("interface %q has no link local IPv6 address", iface.Name)
}

func listInterfaces(w io.Writer, noColor bool) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	indent := "     "

	for _, iface := range ifaces {
		fmt.Fprintf(w, "\n%2d: %s %s:\n", iface.Index,
			styled(iface.Name, noColor, bold, fgRed), styled("<"+iface.Flags.String()+">", noColor, faint))

		if iface.HardwareAddr != nil {
			fmt.Fprintf(w, "%sMAC : %s\n", indent, styled(iface.HardwareAddr.String(), noColor, bold))
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("gather addresses of interface %q: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			ip, ok := addr.(*net.IPNet)
			if !ok {
				return fmt.Errorf("unexpected IP type: %T", addr)
			}

			ipType := "IPv6"
			if ip.IP.To4() != nil {
				ipType = "IPv4"
			}

			fmt.Fprintf(w, "%s%s: %s %s\n", indent, ipType, styled(addr.String(), noColor, bold),
				styled(ipProperties(ip.IP), noColor, faint))
		}
	}

	return nil
}

func ipProperties(ip net.IP) string {
	properties := []string{}
	if ip.IsLoopback() {
		properties = append(properties, "loopback")
	}

	if ip.IsGlobalUnicast() {
		properties = append(properties, "global unicast")
	}

	if ip.IsLinkLocalUnicast() {
		properties = append(properties, "link local unicast")
	}

	if ip.IsMulticast() {
		properties = append(properties, "multicast")
	}

	return "<" + strings.Join(properties, "|") + ">"
}

type interfaceError struct {
	error
}

func (ie interfaceError) Error() string {
	return ie.error.Error()
}

func formatStopAfter(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}

	now := time.Now()
	stopTime := now.Add(d)

	dateFormatter := "03:04pm"
	if stopTime.Day() != now.Day() {
		dateFormatter += " 02-Jan-06"
	}

	return fmt.Sprintf("%s (%s)", d.String(), stopTime.Format(dateFormatter))
}

func toUpper(elements []string) []string {
	upper := make([]string, 0, len(elements))

	for _, el := range elements {
		upper = append(upper, strings.ToUpper(el))
	}

	return upper
}

func asDNSServerAddress(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "53"
	}

	ip, err := hostToIP(host)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(ip.String(), port), nil
}

func hostToIP(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultLookupTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: empty response", host)
	}

	return ips[0], nil
}

func binaryName() string {
	binary, err := os.Executable()
	if err == nil {
		return filepath.Base(binary)
	}

	if len(os.Args) != 0 && !strings.HasPrefix(os.Args[0], "-") {
		return filepath.Base(os.Args[0])
	}

	return "pretender"
}
