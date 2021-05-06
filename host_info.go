package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	execDeadlineWindows = 800 * time.Millisecond
	execDeadlineLinux   = 250 * time.Millisecond
	osWindows           = "windows"
	osLinux             = "linux"
)

//go:embed mac-vendors.txt
var macVendorsFile string

type macIPPair struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// HostInfoCache caches information such as IPv4 addresses, MAC vendors and hostnames.
type HostInfoCache struct {
	macIPPairs      []macIPPair
	ipv6ToHostnames map[string][]string
	ipv4ToHostnames map[string][]string
	macVendors      map[string]string

	sync.Mutex
}

// NewHostInfoCache returns a new HostInfoCache and parses the embedded MAC vendors file.
func NewHostInfoCache() *HostInfoCache {
	cache := &HostInfoCache{
		macIPPairs:      []macIPPair{},
		ipv6ToHostnames: map[string][]string{},
		ipv4ToHostnames: map[string][]string{},
		macVendors:      map[string]string{},
	}

	scanner := bufio.NewScanner(strings.NewReader(macVendorsFile))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 3) // nolint:gomnd
		if len(parts) < 2 || parts[0] == "#" {
			continue
		}

		cache.macVendors[parts[0]] = parts[1]
	}

	return cache
}

// SaveMACFromIP saves the MAC address extracted from the IP together with the
// IP in the cache.
func (c *HostInfoCache) SaveMACFromIP(ip net.IP, fallback net.HardwareAddr) {
	c.Lock()
	defer c.Unlock()

	for _, pair := range c.macIPPairs {
		if ip.Equal(pair.IP) {
			return
		}
	}

	mac := extractMAC(ip)
	if mac == nil {
		if fallback == nil {
			return
		}

		mac = net.HardwareAddr{fallback[0], fallback[1], fallback[2], 0, 0, 0} // use fallback only for vendor prefix
	}

	c.macIPPairs = append(c.macIPPairs, macIPPair{IP: ip, MAC: mac})
}

func (c *HostInfoCache) toMAC(ip net.IP) net.HardwareAddr {
	for _, pair := range c.macIPPairs {
		if ip.Equal(pair.IP) {
			return pair.MAC
		}
	}

	mac := getMACFromOS(ip)
	if mac != nil {
		c.macIPPairs = append(c.macIPPairs, macIPPair{IP: ip, MAC: mac})
	}

	return mac
}

func (c *HostInfoCache) toIPv4(ip net.IP) net.IP {
	if ip.To4() != nil {
		return ip
	}

	mac := c.toMAC(ip)
	if mac == nil {
		return nil
	}

	for _, pair := range c.macIPPairs {
		if bytes.Equal(mac, pair.MAC) && pair.IP.To4() != nil {
			return pair.IP
		}
	}

	ipv4 := getIPFromARP(mac)
	if ipv4 != nil {
		c.macIPPairs = append(c.macIPPairs, macIPPair{MAC: mac, IP: ipv4})
	}

	return ipv4
}

func (c *HostInfoCache) toIPv6(ip net.IP) net.IP {
	if ip.To4() == nil {
		return ip
	}

	mac := c.toMAC(ip)

	for _, pair := range c.macIPPairs {
		if bytes.Equal(mac, pair.MAC) && pair.IP.To4() == nil {
			return pair.IP
		}
	}

	return nil
}

func (c *HostInfoCache) hostnames(ip net.IP) []string {
	var results []string

	ipv4 := c.toIPv4(ip)
	if ipv4 != nil {
		hostnames, ok := c.ipv4ToHostnames[ipv4.String()]
		if !ok {
			hostnames = reverseLookup(ipv4.String())

			c.ipv4ToHostnames[ipv4.String()] = hostnames
		}

		results = append(results, hostnames...)
	}

	ipv6 := c.toIPv6(ip)
	if ipv4 != nil {
		hostnames, ok := c.ipv6ToHostnames[ipv6.String()]
		if !ok {
			hostnames = reverseLookup(ipv6.String())

			c.ipv6ToHostnames[ipv6.String()] = hostnames
		}

		results = append(results, hostnames...)
	}

	return unique(results)
}

func (c *HostInfoCache) vendor(ip net.IP) string {
	if c.macVendors == nil {
		return ""
	}

	mac := c.toMAC(ip)
	if mac == nil {
		return ""
	}

	return c.macVendors[strings.ToUpper(mac.String()[:8])]
}

func unique(input []string) []string {
	present := map[string]bool{}

	unique := []string{}

	for _, el := range input {
		if !present[el] {
			present[el] = true

			unique = append(unique, el)
		}
	}

	return unique
}

const reverseDNSTimeout = 200 * time.Millisecond

func reverseLookup(addr string) []string {
	if addr == "" {
		return nil
	}

	resultChannel := make(chan []string)

	go func() {
		defer close(resultChannel)

		addrs, err := net.LookupAddr(addr)
		if err != nil {
			resultChannel <- nil
		}

		resultChannel <- addrs
	}()

	select {
	case result := <-resultChannel:
		return trimRightSlice(result, ".")
	case <-time.After(reverseDNSTimeout):
		return nil
	}
}

func trimRightSlice(stringSlice []string, cutset string) []string {
	result := make([]string, 0, len(stringSlice))

	for _, element := range stringSlice {
		result = append(result, strings.TrimRight(element, cutset))
	}

	return result
}

// HostInfos returns the string representations of all available infos for the
// host.
func (c *HostInfoCache) HostInfos(ip net.IP) []string {
	c.Lock()
	defer c.Unlock()

	var infos []string

	if ip.To4() == nil {
		ipv4 := c.toIPv4(ip)
		if ipv4 != nil {
			infos = append(infos, ipv4.String())
		}
	}

	hostnames := c.hostnames(ip)

	if len(hostnames) == 0 {
		// add MAC vendor as replacement for missing hostnames
		vendor := c.vendor(ip)
		if vendor != "" {
			infos = append(infos, vendor)
		}
	}

	return append(hostnames, infos...)
}

// HostInfoAnnotation returns the infos for the IP in the form of an annotation
// and an empty string if no infos are available.
func (c *HostInfoCache) HostInfoAnnotation(ip net.IP) string {
	infos := c.HostInfos(ip)
	if len(infos) == 0 {
		return ip.String()
	}

	return fmt.Sprintf("%s (%s)", ip, strings.Join(infos, ", "))
}

func getMACFromIPNeighLinux(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), execDeadlineLinux)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "neighbour")

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " ", 6) // nolint:gomnd
		if len(parts) < 6 {                             // nolint:gomnd
			continue
		}

		if !ip.Equal(net.ParseIP(parts[0])) {
			continue
		}

		mac, err := net.ParseMAC(parts[4])
		if err == nil {
			return mac
		}
	}

	return nil
}

func getMACFromNetshShowNeighborsWindows(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), execDeadlineWindows)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv6", "show", "neighbors")

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 { // nolint:gomnd
			continue
		}

		if !ip.Equal(net.ParseIP(parts[0])) {
			continue
		}

		if parts[2] == "Unreachable" {
			continue
		}

		mac, err := net.ParseMAC(strings.ReplaceAll(strings.ToUpper(parts[1]), "-", ":"))
		if err == nil {
			return mac
		}
	}

	return nil
}

func getMACFromARPLinux(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}

	arpTable, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(arpTable), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 6 { // nolint:gomnd
			continue
		}

		if ip.Equal(net.ParseIP(parts[0])) {
			mac, err := net.ParseMAC(parts[3])
			if err == nil {
				return mac
			}
		}
	}

	return nil
}

func getIPFromARPLinux(mac net.HardwareAddr) net.IP {
	if mac == nil {
		return nil
	}

	arpTable, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(arpTable), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 6 { // nolint:gomnd
			continue
		}

		if strings.EqualFold(mac.String(), parts[3]) {
			ip := net.ParseIP(parts[0])
			if ip != nil {
				return ip
			}
		}
	}

	return nil
}

// nolint:gomnd
func getMACFromARPWindows(ip net.IP) net.HardwareAddr {
	ctx, cancel := context.WithTimeout(context.Background(), execDeadlineWindows)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", "-a")

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	skip := false

	for _, line := range strings.Split(string(output), "\n") {
		if len(line) == 0 {
			continue
		}

		if line[0] != ' ' {
			skip = true

			continue
		}

		if skip {
			skip = false

			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		lineIP := net.ParseIP(fields[0])
		if !ip.Equal(lineIP) {
			continue
		}

		mac, err := net.ParseMAC(strings.ReplaceAll(fields[1], "-", ":"))
		if err == nil {
			return mac
		}
	}

	return nil
}

func getIPFromARPWindows(mac net.HardwareAddr) net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), execDeadlineWindows)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", "-a")

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	skip := false

	for _, line := range strings.Split(string(output), "\n") {
		if len(line) == 0 {
			continue
		}

		if line[0] != ' ' {
			skip = true

			continue
		}

		if skip {
			skip = false

			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 { // nolint:gomnd
			continue
		}

		lineMAC, err := net.ParseMAC(strings.ReplaceAll(fields[1], "-", ":"))
		if err != nil || !strings.EqualFold(lineMAC.String(), mac.String()) {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip != nil {
			return ip
		}
	}

	return nil
}

func getIPFromARP(mac net.HardwareAddr) net.IP {
	if runtime.GOOS == osWindows {
		return getIPFromARPWindows(mac)
	}

	return getIPFromARPLinux(mac)
}

func getMACFromOS(ip net.IP) net.HardwareAddr {
	switch runtime.GOOS {
	case osLinux:
		if ip.To4() == nil {
			return getMACFromIPNeighLinux(ip)
		}

		return getMACFromARPLinux(ip)
	case osWindows:
		if ip.To4() == nil {
			return getMACFromNetshShowNeighborsWindows(ip)
		}

		return getMACFromARPWindows(ip)
	default:
		return nil
	}
}

func extractMAC(ip net.IP) net.HardwareAddr {
	if ip[11] != 0xff || ip[12] != 0xfe {
		return getMACFromOS(ip)
	}

	mac := make([]byte, 0, 6) // nolint:gomnd

	// remove ff:fe from the middle
	mac = append(mac, ip[8:11]...)
	mac = append(mac, ip[13:]...)

	// invert bit in first octet
	mac[0] ^= 2

	return mac
}
