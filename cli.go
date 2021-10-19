package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

var version = "compiled from source code"

// Config holds the configuration.
type Config struct {
	RelayIPv4     net.IP
	RelayIPv6     net.IP
	Interface     *net.Interface
	TTL           time.Duration
	LeaseLifetime time.Duration
	LocalIPv6     net.IP
	RAPeriod      time.Duration

	NoDHCPv6DNSTakeover   bool
	NoMDNS                bool
	NoNetBIOS             bool
	NoLLMNR               bool
	NoLocalNameResolution bool
	NoRA                  bool
	NoIPv6LNR             bool

	Spoof        []string
	DontSpoof    []string
	SpoofFor     []net.IP
	DontSpoofFor []net.IP
	DryMode      bool

	StopAfter      time.Duration
	Verbose        bool
	NoColor        bool
	NoTimestamps   bool
	NoHostInfo     bool
	ListInterfaces bool
}

// PrintSummary prints a summary of some important configuration parameters.
// nolint:forbidigo
func (c Config) PrintSummary() {
	fmt.Printf("Listening on interface: %s\n", c.Interface.Name)

	if c.RelayIPv4 != nil {
		fmt.Printf("IPv4 relayed to: %s\n", c.RelayIPv4)
	}

	if c.RelayIPv6 != nil {
		fmt.Printf("IPv6 relayed to: %s\n", c.RelayIPv6)
	}

	if len(c.Spoof) != 0 {
		fmt.Println("Answering queries for: " + strings.Join(c.Spoof, ", "))
	}

	if len(c.DontSpoof) != 0 {
		fmt.Println("Ignoring queries for: " + strings.Join(c.DontSpoof, ", "))
	}

	if len(c.SpoofFor) != 0 {
		fmt.Println("Answering queries from: " + joinIPs(c.SpoofFor, ", "))
	}

	if len(c.DontSpoofFor) != 0 {
		fmt.Println("Ignoring queries from: " + joinIPs(c.DontSpoofFor, ", "))
	}

	fmt.Println()
}

// nolint:forbidigo
func configFromCLI() (config Config, logger *Logger, err error) {
	var (
		interfaceName string
		printVersion  bool
	)

	pflag.StringVarP(&interfaceName, "interface", "i", defaultInterface, "Interface to bind on, supports autodetection")
	pflag.IPVarP(&config.RelayIPv4, "ip4", "4", defaultRelayIPv4,
		"Relay IPv4 address with which queries are answered, supports autodetection")
	pflag.IPVarP(&config.RelayIPv6, "ip6", "6", defaultRelayIPv6,
		"Relay IPv6 address with which queries are answered, supports autodetection")

	pflag.BoolVar(&config.NoDHCPv6DNSTakeover, "no-dhcp", defaultNoDHCPv6DNSTakeover, "Disable DHCPv6 DNS Takeover")
	pflag.BoolVar(&config.NoMDNS, "no-mdns", defaultNoMDNS, "Disable mDNS spoofing")
	pflag.BoolVar(&config.NoNetBIOS, "no-netbios", defaultNoNetBIOS, "Disable NetBIOS-NS spoofing")
	pflag.BoolVar(&config.NoLLMNR, "no-llmnr", defaultNoLLMNR, "Disable LLMNR spoofing")
	pflag.BoolVar(&config.NoLocalNameResolution, "no-lnr", defaultNoLocalNameResolution,
		"Disable local name resolution (mDNS, LLMNR, NetBIOS-NS)")
	pflag.BoolVar(&config.NoRA, "no-ra", defaultNoRA, "Disable router advertisement")
	pflag.BoolVar(&config.NoIPv6LNR, "no-ipv6-lnr", defaultNoIPv6LNR,
		"Disable mDNS and LLMNR via IPv6 (useful with allowlist or blocklist)")

	pflag.StringSliceVar(&config.Spoof, "spoof", defaultSpoof,
		"Only spoof these domains, if domain starts with a dot, all subdomains with match (allowlist)")
	pflag.StringSliceVar(&config.DontSpoof, "dont-spoof", defaultDontSpoof,
		"Do not spoof these domains, if domain starts with a dot, all subdomains with match (blocklist)")
	pflag.IPSliceVar(&config.SpoofFor, "spoof-for", defaultSpoofFor, "Only spoof domains for these IPs (allowlist)")
	pflag.IPSliceVar(&config.DontSpoofFor, "dont-spoof-for", defaultDontSpoofFor,
		"Do not spoof domains for these IPs (blocklist)")
	pflag.BoolVar(&config.DryMode, "dry", defaultDryMode,
		"No not spoof domains at all, only log queries (DHCPv6 will still be active)")

	pflag.DurationVarP(&config.TTL, "ttl", "t", defaultTTL, "Time to live for name resolution responses")
	pflag.DurationVar(&config.LeaseLifetime, "lease-time", defaultLeaseLifetime, "DHCPv6 IP lease lifetime")
	pflag.DurationVar(&config.RAPeriod, "ra-period", defaultRAPeriod, "Time period between router advertisements")

	pflag.DurationVar(&config.StopAfter, "stop-after", defaultStopAfter, "Stop running after this duration")
	pflag.BoolVarP(&config.Verbose, "verbose", "v", defaultVerbose, "Print debug information")
	pflag.BoolVar(&config.NoColor, "no-color", defaultNoColor, "Disables output styling")
	pflag.BoolVar(&config.NoTimestamps, "no-timestamps", defaultNoTimestamps, "Disables timestamps in the output")
	pflag.BoolVar(&printVersion, "version", false, "Print version information")
	pflag.BoolVar(&config.NoHostInfo, "no-host-info", defaultNoHostInfo, "Do not gather host information")
	pflag.BoolVar(&config.ListInterfaces, "interfaces", defaultListInterfaces,
		"List interfaces and their addresses for a platform-independent way to"+
			"identify the correct interface (other options have no effect except for --no-color)")

	pflag.CommandLine.SortFlags = false

	pflag.Parse()

	if pflag.NArg() > 0 {
		fmt.Printf("%s does not take positional arguments, only the following flags\n\n", os.Args[0])
		pflag.PrintDefaults()

		os.Exit(1)
	}

	fmt.Println("Pretender " + version)

	if config.ListInterfaces {
		err := listInterfaces(os.Stdout, config.NoColor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v", err)

			os.Exit(1)
		}

		os.Exit(0)
	}

	if printVersion {
		fmt.Println("What if I say I'll never Responder")

		os.Exit(0)
	}

	logger = NewLogger()
	logger.Verbose = config.Verbose
	logger.NoColor = config.NoColor
	logger.PrintTimestamps = !config.NoTimestamps
	logger.NoHostInfo = config.NoHostInfo

	config.Interface, err = chooseInterface(interfaceName, config.RelayIPv4, config.RelayIPv6)
	if err != nil {
		return config, logger, interfaceError{err}
	}

	var errIPv4, errIPv6 error

	config.RelayIPv4, errIPv4 = autoConfigureRelayIPv4(config.Interface, config.RelayIPv4, config.RelayIPv6)
	config.RelayIPv6, errIPv6 = autoConfigureRelayIPv6(config.Interface, config.RelayIPv4, config.RelayIPv6)

	if config.RelayIPv4 == nil && (!config.NoNetBIOS && !config.NoLLMNR) {
		return config, logger, fmt.Errorf("no relay IPv4 available (required for NetBIOS name resoltion): %w", errIPv4)
	}

	if config.RelayIPv6 == nil && config.RelayIPv4 == nil {
		return config, logger, fmt.Errorf("no relay IP available: %s and %s", errIPv4, errIPv6) // nolint:errorlint
	}

	config.LocalIPv6, err = getLinkLocalIPv6Address(config.Interface)
	if err != nil && !config.NoDHCPv6DNSTakeover {
		return config, logger, fmt.Errorf("cannot detect link local IPv6 (required for DHCPv6 DNS Takeover: %w", err)
	}

	config.PrintSummary()

	return config, logger, nil
}

func joinIPs(ips []net.IP, sep string) string {
	ipStrings := make([]string, 0, len(ips))

	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return strings.Join(ipStrings, sep)
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

// nolint:cyclop
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
		return nil, fmt.Errorf("cannot detect interface when no relay addresses are provided")
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
			return nil, fmt.Errorf("auto detecting IPv4: %w", err)
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
			return nil, fmt.Errorf("auto detecting IPv6: %w", err)
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
