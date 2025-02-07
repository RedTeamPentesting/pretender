package main

import (
	"context"
	"errors"
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
	RelayIPv4         net.IP
	RelayIPv6         net.IP
	SOAHostname       string
	SpoofResponseName string
	Interface         *net.Interface
	TTL               time.Duration
	LeaseLifetime     time.Duration
	RouterLifetime    time.Duration
	LocalIPv6         net.IP
	RAPeriod          time.Duration
	StatelessRA       bool
	DNSTimeout        time.Duration

	NoDHCPv6DNSTakeover   bool
	NoDHCPv6              bool
	NoDNS                 bool
	NoMDNS                bool
	NoNetBIOS             bool
	NoLLMNR               bool
	NoLocalNameResolution bool
	NoIPv6LNR             bool
	NoRA                  bool
	NoRADNS               bool

	Spoof                        []*hostMatcher
	DontSpoof                    []*hostMatcher
	SpoofFor                     []*hostMatcher
	DontSpoofFor                 []*hostMatcher
	SpoofTypes                   *spoofTypes
	IgnoreDHCPv6NoFQDN           bool
	IgnoreNonMicrosoftDHCP       bool
	DelegateIgnoredTo            string
	ToggleNameResolutionSpoofing bool
	DontSendEmptyReplies         bool
	DryMode                      bool
	DryWithDHCPv6Mode            bool

	StopAfter      time.Duration
	Verbose        bool
	NoColor        bool
	NoTimestamps   bool
	LogFileName    string
	NoHostInfo     bool
	HideIgnored    bool
	RedirectStderr bool
	ListInterfaces bool

	spoof                       []string
	dontSpoof                   []string
	spoofFor                    []string
	dontSpoofFor                []string
	spoofTypes                  []string
	spoofingTemporarilyDisabled bool
}

// PrintSummary prints a summary of some important configuration parameters.
//
//nolint:forbidigo,gocognit
func (c Config) PrintSummary() {
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
		raNotice := ""
		if !c.NoRA && !c.NoDHCPv6DNSTakeover && !c.NoDHCPv6 {
			raNotice = " (RA is still enabled)"
		}

		drySubject := "DHCPv6 and name resolution queries"
		if c.DryWithDHCPv6Mode {
			drySubject = "Name resolution queries"
		}

		fmt.Printf("Dry Mode: %s will not be answered%s\n", drySubject, raNotice)
	default:
		if len(c.Spoof) != 0 {
			fmt.Println("Answering queries for: " + joinHosts(c.Spoof))
		}

		if len(c.DontSpoof) != 0 {
			fmt.Println("Ignoring queries for: " + joinHosts(c.DontSpoof))
		}

		if len(c.SpoofFor) != 0 {
			fmt.Println("Answering queries from: " + joinHosts(c.SpoofFor))
		}

		if len(c.DontSpoofFor) != 0 {
			fmt.Println("Ignoring queries from: " + joinHosts(c.DontSpoofFor))
		}

		if len(c.spoofTypes) != 0 {
			fmt.Println("Answering only queries of type: " + strings.Join(toUpper(c.spoofTypes), ", "))
		}
	}

	if c.DelegateIgnoredTo != "" {
		fmt.Println("Ignored DNS queries are delegated to DNS server:", c.DelegateIgnoredTo)
	}

	if c.StatelessRA {
		dhcp := ""
		if !c.NoDHCPv6 {
			dhcp = " (DHCPv6 server is still active)"
		}

		fmt.Println("Stateless DNS configuration via Router Advertisement enabled" + dhcp)

		if c.DelegateIgnoredTo == "" && (len(c.SpoofFor) > 0 || len(c.DontSpoofFor) > 0) {
			fmt.Println(c.style(fgYellow, bold) + "Warning:" + c.style(reset) + c.style(fgYellow) +
				" In stateless mode, the DNS server is sent to all neighbors regardless of --spoof-for/--dont-spoof-for" +
				" setting, use --delegate-ignored-to to avoid affecting uninteded hosts" + c.style(reset))
		}
	}

	if c.SpoofResponseName != "" {
		fmt.Println("DNS/LLMNR response names spoofed as:", c.SpoofResponseName)

		if c.NoLLMNR && c.NoDNS {
			fmt.Println(c.style(fgYellow, bold) + "Warning:" + c.style(reset) + c.style(fgYellow) +
				" Response name spoofing is enabled but LLMNR and DNS are disabled" + c.style())
		}
	}

	if c.StopAfter > 0 {
		fmt.Printf("Pretender will automatically terminate after: %s\n", formatStopAfter(c.StopAfter))
	}

	if c.ToggleNameResolutionSpoofing {
		fmt.Printf("Toggle Name Resolution Spoofing (does not affect DHCPv6/RA): %s\n",
			nameResolutionToggleShortcutInfo)
	}

	fmt.Println()
}

func (c *Config) style(attrs ...attribute) string {
	if c.NoColor {
		return ""
	}

	if len(attrs) == 0 {
		attrs = append(attrs, 0)
	}

	s := ""
	for _, a := range attrs {
		s += fmt.Sprintf("%s[%dm", escape, a)
	}

	return s
}

func (c *Config) setRedundantOptions() {
	if c.DryWithDHCPv6Mode {
		c.DryMode = true
	}

	if c.NoDNS && c.NoDHCPv6 {
		c.NoDHCPv6DNSTakeover = true
	} else if c.NoDHCPv6DNSTakeover {
		c.NoDHCPv6 = true
		c.NoDNS = true
	}

	if !c.StatelessRA && c.NoDHCPv6 {
		c.NoRA = true
	}

	if c.NoMDNS && c.NoLLMNR && c.NoNetBIOS {
		c.NoLocalNameResolution = true
	}

	if c.NoLocalNameResolution {
		c.NoNetBIOS = true
		c.NoLLMNR = true
		c.NoMDNS = true
	}

	if (c.NoDHCPv6DNSTakeover || c.NoDNS) || (c.NoDHCPv6 && !c.StatelessRA) {
		c.NoRADNS = true
	}

	// don't advertize DNS server in RA when --spoof-for or --dont-spoof-for
	// filters are present because it will set DNS for all hosts
	// if --delegate-ignored-to is specified this is not really a problem
	if !c.StatelessRA && c.DelegateIgnoredTo == "" && (len(c.spoofFor) != 0 || len(c.dontSpoofFor) != 0) {
		c.NoRADNS = true
	}
}

//nolint:forbidigo,maintidx,gocognit
func configFromCLI() (config *Config, logger *Logger, err error) {
	var (
		interfaceName string
		printVersion  bool
	)

	config = &Config{}

	pflag.StringVarP(&interfaceName, "interface", "i", defaultInterface,
		"Interface to bind on, supports auto-detection by IPv4 or IPv6")
	pflag.IPVarP(&config.RelayIPv4, "ipv4", "4", defaultRelayIPv4,
		"Relay IPv4 address with which queries are answered, supports\nauto-detection by interface")
	pflag.IPVarP(&config.RelayIPv6, "ipv6", "6", defaultRelayIPv6,
		"Relay IPv6 address with which queries are answered, supports\nauto-detection by interface")
	pflag.StringVar(&config.SOAHostname, "soa-hostname", defaultSOAHostname,
		"Hostname for the SOA record (useful for Kerberos relaying)")
	pflag.StringVar(&config.SpoofResponseName, "spoof-response-name", defaultSpoofResponseName,
		"Spoof response name to influnce SPNs (works with DNS and LLMNR, NetBIOS and mDNS will be ignored)")

	pflag.BoolVar(&config.NoDHCPv6DNSTakeover, "no-dhcp-dns", defaultNoDHCPv6DNSTakeover,
		"Disable DHCPv6 DNS takeover attack (DHCPv6 and DNS, mutually\nexlusive with --stateless-ra)")
	pflag.BoolVar(&config.NoDHCPv6, "no-dhcp", defaultNoDHCPv6, "Disable DHCPv6 spoofing")
	pflag.BoolVar(&config.NoDNS, "no-dns", defaultNoDNS, "Disable DNS spoofing")
	pflag.BoolVar(&config.NoMDNS, "no-mdns", defaultNoMDNS, "Disable mDNS spoofing")
	pflag.BoolVar(&config.NoNetBIOS, "no-netbios", defaultNoNetBIOS, "Disable NetBIOS-NS spoofing")
	pflag.BoolVar(&config.NoLLMNR, "no-llmnr", defaultNoLLMNR, "Disable LLMNR spoofing")
	pflag.BoolVar(&config.NoLocalNameResolution, "no-lnr", defaultNoLocalNameResolution,
		"Disable local name resolution spoofing (mDNS, LLMNR, NetBIOS-NS)")
	pflag.BoolVar(&config.NoIPv6LNR, "no-ipv6-lnr", defaultNoIPv6LNR,
		"Disable mDNS and LLMNR via IPv6 (useful with allowlist or blocklist)")
	pflag.BoolVar(&config.NoRA, "no-ra", defaultNoRA, "Disable router advertisements")
	pflag.BoolVar(&config.NoRADNS, "no-ra-dns", defaultNoRADNS,
		"Disable DNS server advertisement via RA (useful because\nRA is not affected by --spoof/--spoof-for filters)")

	pflag.StringSliceVar(&config.spoof, "spoof", defaultSpoof,
		"Only spoof these domains, includes subdomain if it starts with\na dot, a single dot "+
			"matches local hostnames,\nsupports * globbing (allowlist)")
	pflag.StringSliceVar(&config.dontSpoof, "dont-spoof", defaultDontSpoof,
		"Do not spoof these domains, includes subdomains if it starts\nwitha dot, a single dot "+
			"matches local hostnames,\nsupports * globbing (blocklist)")
	pflag.StringSliceVar(&config.spoofFor, "spoof-for", defaultSpoofFor,
		"Only spoof DHCPv6 and name resolution for these `hosts`, it can\ncontain IPs or hostnames "+
			"and subdomains are included when the hostname\nstarts with a dot, supports * globbing (allowlist)")
	pflag.StringSliceVar(&config.dontSpoofFor, "dont-spoof-for", defaultDontSpoofFor,
		"Do not spoof DHCPv6 and name resolution for these `hosts`, it can\ncontain IPs or hostnames "+
			"and subdomains are included when the hostname\nstarts with a dot, supports * globbing (blocklist)")
	pflag.StringSliceVar(&config.spoofTypes, "spoof-types", defaultSpoofTypes,
		"Only spoof these query `types` (A, AAA, ANY, SOA, all types are spoofed\nif it is empty)")
	pflag.BoolVar(&config.IgnoreDHCPv6NoFQDN, "ignore-nofqdn", defaultIgnoreDHCPv6NoFQDN,
		"Ignore DHCPv6 messages where the client did not include its\nFQDN (useful with allowlist or blocklists)")
	pflag.BoolVar(&config.IgnoreNonMicrosoftDHCP, "ignore-non-microsoft-dhcp", defaultIgnoreNonMicrosoftDHCP,
		"Ignore DHCPv6 messages where the client did not include Microsoft's enterprise number")
	pflag.StringVar(&config.DelegateIgnoredTo, "delegate-ignored-to", defaultDelegateIgnoredTo,
		"Delegate ignored DNS queries to an upstream `DNS server`")
	pflag.BoolVar(&config.ToggleNameResolutionSpoofing, "toggle", defaultToggleNameResolutionSpoofing,
		"Enable toggling of name resoluton spoofing at runtime ("+nameResolutionToggleShortcutInfo+")")
	pflag.BoolVar(&config.DontSendEmptyReplies, "dont-send-empty-replies", defaultDontSendEmptyReplies,
		"Don't reply at all to ignored DNS queries or failed delegated\nqueries instead of sending an empty reply")
	pflag.BoolVar(&config.DryMode, "dry", defaultDryMode,
		"Do not answer DHCPv6 or any name resolution queries, only log them\n"+
			"(does not disable RA but it can be combined with --no-ra/--no-ra-dns)")
	pflag.BoolVar(&config.DryWithDHCPv6Mode, "dry-with-dhcp", defaultDryWithDHCPMode,
		"Send RA and answer DHCPv6 queries but only log name resolution\n"+
			"queries (can be combined with --delegate-ignored-to, takes\nprecedence over --dry)")
	pflag.BoolVar(&config.StatelessRA, "stateless-ra", defaultStatelessRA,
		"Do not advertize DHCPv6 server in router advertisement, only DNS\n"+
			"server (useful with --no-dhcp, mutually exclusive with\n--no-ra/--no-ra-dns/--no-dhcp-dns)")

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

	config.setRedundantOptions()

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
		f, err := os.OpenFile(config.LogFileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) //nolint:mnd
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

	if config.NoRADNS && config.StatelessRA {
		return config, logger, fmt.Errorf("--no-ra-dns/--no-dhcp-dns and --stateless-ra are mutually exclusive")
	} else if config.NoRA && config.StatelessRA {
		return config, logger, fmt.Errorf("--no-ra and --stateless-ra are mutually exclusive")
	}

	config.Interface, err = chooseInterface(interfaceName, config.RelayIPv4, config.RelayIPv6)
	if err != nil {
		return config, logger, interfaceError{err}
	}

	relayIPv4, errIPv4 := autoDetectRelayIPv4(config.Interface, config.RelayIPv4, config.RelayIPv6)
	relayIPv6, errIPv6 := autoDetectRelayIPv6(config.Interface, config.RelayIPv4, config.RelayIPv6)
	config.RelayIPv4 = relayIPv4
	config.RelayIPv6 = relayIPv6

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

	config.Spoof, err = asHostMatchers(config.spoof, false, config.DNSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("parse spoof: %w", err)
	}

	config.DontSpoof, err = asHostMatchers(config.dontSpoof, false, config.DNSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dont-spoof: %w", err)
	}

	config.SpoofFor, err = asHostMatchers(config.spoofFor, true, config.DNSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("parse spoof-for: %w", err)
	}

	config.DontSpoofFor, err = asHostMatchers(config.dontSpoofFor, true, config.DNSTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dont-spoof-for: %w", err)
	}

	config.SpoofTypes, err = parseSpoofTypes(config.spoofTypes)
	if err != nil {
		return config, logger, fmt.Errorf("parsing --spoof-types: %w", err)
	}

	config.PrintSummary()

	return config, logger, nil
}

func joinHosts(hosts []*hostMatcher) string {
	hostStrings := make([]string, 0, len(hosts))

	for _, ip := range hosts {
		hostStrings = append(hostStrings, ip.String())
	}

	return strings.Join(hostStrings, ", ")
}

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

func autoDetectRelayIPv4(iface *net.Interface, ipv4, ipv6 net.IP) (net.IP, error) {
	if ipv4 == nil {
		if ipv6 != nil {
			return nil, fmt.Errorf("IPv4 auto-detection is disabled when an IPv6 relay address is specified")
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

func autoDetectRelayIPv6(iface *net.Interface, ipv4, ipv6 net.IP) (net.IP, error) {
	if ipv6 == nil {
		if ipv4 != nil {
			return nil, fmt.Errorf("IPv6 auto-detection is disabled when an IPv4 relay address is specified")
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

		if ip.IP.To4() == nil && ip.IP.IsLinkLocalUnicast() {
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

func stripSpaces(elements []string) {
	for i, el := range elements {
		elements[i] = strings.TrimSpace(el)
	}
}

func processInputSignals(ctx context.Context, logger *Logger, cfg *Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	exitSemiRawMode, err := enterSemiRawMode()
	if err != nil {
		return fmt.Errorf("enable raw mode: %w", err)
	}

	errChan := make(chan error, 1)

	go func() {
		err = handleInput(ctx, logger, cfg)
		if err != nil {
			errChan <- err
		} else {
			close(errChan)
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Errorf("cannot read terminal input: %v", err)
		}

		cancel()
	}

	err = exitSemiRawMode()
	if err != nil {
		logger.Errorf("cannot restore terminal: %v", err)
	}

	return nil
}

func handleInput(ctx context.Context, logger *Logger, cfg *Config) error {
	buf := make([]byte, 1)

	for ctx.Err() == nil {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}

		if ctx.Err() != nil {
			return context.Cause(ctx)
		}

		if n == 0 {
			continue
		}

		switch buf[0] {
		case 's', 'S':
			logger.NotifySpoofingStatus(!cfg.spoofingTemporarilyDisabled)
		case 'e', 'E':
			cfg.spoofingTemporarilyDisabled = false

			logger.NotifySpoofingEnabled()
		case 'd', 'D':
			cfg.spoofingTemporarilyDisabled = true

			logger.NotifySpoofingDisabled()
		case 't', 'T':
			cfg.spoofingTemporarilyDisabled = !cfg.spoofingTemporarilyDisabled

			logger.NotifySpoofingToggled(!cfg.spoofingTemporarilyDisabled)
		case '\n', '\r':
			fmt.Println()
		}
	}

	return context.Cause(ctx)
}
