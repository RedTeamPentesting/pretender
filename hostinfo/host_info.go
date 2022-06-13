// Package hostinfo can be used to correlate IPs, MACs and hostnames using
// caches DNS lookups and ARP information.
package hostinfo

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	execTimeoutWindows = 800 * time.Millisecond
	execTimeoutLinux   = 250 * time.Millisecond

	osWindows = "windows"
	osLinux   = "linux"

	macPrefixLength = 8
)

var testMode = false

//go:embed mac-vendors.txt
var macVendorsFile string

type macIPPair struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// Cache caches information such as IPv4 addresses, MAC vendors and hostnames.
type Cache struct {
	macIPPairs        []macIPPair
	resolvedHostnames map[string][]string
	externalHostnames map[string][]string
	resolvedIPs       map[string][]net.IP
	macVendors        map[string]string

	sync.Mutex
}

// NewCache returns a new HostInfoCache and parses the embedded MAC vendors file.
func NewCache() *Cache {
	cache := &Cache{
		macIPPairs:        []macIPPair{},
		resolvedHostnames: map[string][]string{},
		externalHostnames: map[string][]string{},
		resolvedIPs:       map[string][]net.IP{},
		macVendors:        map[string]string{},
	}

	scanner := bufio.NewScanner(strings.NewReader(macVendorsFile))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 3) // nolint:gomnd
		if len(parts) < 2 || parts[0] == "#" {
			continue
		}

		// we do only support 3-byte mac prefixes because we may have obtained
		// the mac from a DHCPv6 packet where the remaining bytes may have been
		// anonymized
		if len(parts[0]) > macPrefixLength {
			continue
		}

		cache.macVendors[strings.ToUpper(parts[0])] = parts[1]
	}

	return cache
}

// SaveMACFromIP saves the MAC address extracted from the IP together with the
// IP in the cache. If the IP did not contain an EUI-64 encoded MAC address a
// MAC address with the first three bytes of the provided fallback address is
// saved in order to be able to identify the vendor.
func (c *Cache) SaveMACFromIP(ip net.IP, fallback net.HardwareAddr) {
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

		// use fallback only for vendor prefix
		mac = net.HardwareAddr{fallback[0], fallback[1], fallback[2], 0, 0, 0}
	}

	c.macIPPairs = append(c.macIPPairs, macIPPair{IP: ip, MAC: mac})
}

// AddHostnamesForIP registers a set of hostnames for a given IP that were
// obtained externally. Hostnames are only added if they are not already
// present.
func (c *Cache) AddHostnamesForIP(ip net.IP, hostnames []string) {
	c.Lock()
	defer c.Unlock()

	c.externalHostnames[ip.String()] = appendUnique(c.externalHostnames[ip.String()], hostnames...)
}

func (c *Cache) toMAC(ip net.IP) net.HardwareAddr {
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

func (c *Cache) toIPv4(ip net.IP) net.IP {
	if ip.To4() != nil {
		return ip
	}

	mac := c.toMAC(ip)
	if mac == nil {
		return c.lookupUsingExternalHostnames(ip, mac)
	}

	for _, pair := range c.macIPPairs {
		if bytes.Equal(mac, pair.MAC) && pair.IP.To4() != nil {
			return pair.IP
		}
	}

	ipv4 := getIPFromARP(mac)
	if ipv4 != nil {
		c.macIPPairs = append(c.macIPPairs, macIPPair{MAC: mac, IP: ipv4})

		return ipv4
	}

	if ipv4 == nil {
		return c.lookupUsingExternalHostnames(ip, mac)
	}

	return ipv4
}

func (c *Cache) lookupUsingExternalHostnames(ip net.IP, mac net.HardwareAddr) net.IP {
	externalHostnames := c.externalHostnames[ip.String()]
	if len(externalHostnames) == 0 {
		return nil
	}

	// for now, only consider the first to avoid a lot of DNS requests
	externalHostname := externalHostnames[0]

	resolvedIPs, ok := c.resolvedIPs[externalHostname]
	if !ok {
		resolvedIPs = lookup(externalHostname)

		c.resolvedIPs[externalHostname] = resolvedIPs
	}

	if mac != nil {
		for _, resolvedIP := range resolvedIPs {
			c.macIPPairs = append(c.macIPPairs, macIPPair{MAC: mac, IP: resolvedIP})
		}
	}

	for _, resolvedIP := range resolvedIPs {
		if resolvedIP.To4() != nil {
			return resolvedIP
		}
	}

	return nil
}

func (c *Cache) toIPv6(ip net.IP) net.IP {
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

func (c *Cache) hostnames(ip net.IP) []string {
	var results []string

	ipv4 := c.toIPv4(ip)
	if ipv4 != nil {
		hostnames, ok := c.resolvedHostnames[ipv4.String()]
		if !ok {
			hostnames = reverseLookup(ipv4.String())

			c.resolvedHostnames[ipv4.String()] = hostnames
		}

		results = append(results, hostnames...)
		results = append(results, c.externalHostnames[ipv4.String()]...)
	}

	ipv6 := c.toIPv6(ip)
	if ipv6 != nil {
		hostnames, ok := c.resolvedHostnames[ipv6.String()]
		if !ok {
			hostnames = reverseLookup(ipv6.String())

			c.resolvedHostnames[ipv6.String()] = hostnames
		}

		results = append(results, hostnames...)
		results = append(results, c.externalHostnames[ipv6.String()]...)
	}

	return uniqueLowercase(results)
}

func (c *Cache) vendorByIP(ip net.IP) string {
	if c.macVendors == nil {
		return ""
	}

	return c.vendorByMAC(c.toMAC(ip))
}

func (c *Cache) vendorByMAC(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}

	return c.macVendors[strings.ToUpper(mac.String()[:8])]
}

func uniqueLowercase(input []string) []string {
	present := map[string]bool{}

	unique := []string{}

	for _, element := range input {
		lowercaseElement := strings.ToLower(element)

		if !present[lowercaseElement] {
			present[lowercaseElement] = true

			unique = append(unique, lowercaseElement)
		}
	}

	return unique
}

func appendUnique(oldElements []string, newElements ...string) []string {
	present := map[string]bool{}

	for _, oldElement := range oldElements {
		present[oldElement] = true
	}

	for _, el := range newElements {
		_, ok := present[el]
		if !ok {
			oldElements = append(oldElements, el)
			present[el] = true
		}
	}

	return oldElements
}

const dnsTimeout = 200 * time.Millisecond

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

	timer := time.NewTimer(dnsTimeout)

	select {
	case result := <-resultChannel:
		if !timer.Stop() {
			<-timer.C
		}

		return trimRightSlice(result, ".")
	case <-timer.C:
		return nil
	}
}

func lookup(hostname string) []net.IP {
	if hostname == "" {
		return nil
	}

	resultChannel := make(chan []net.IP)

	go func() {
		defer close(resultChannel)

		addrs, err := net.LookupIP(hostname)
		if err != nil {
			resultChannel <- nil
		}

		resultChannel <- addrs
	}()

	timer := time.NewTimer(dnsTimeout)

	select {
	case result := <-resultChannel:
		if !timer.Stop() {
			<-timer.C
		}

		return result
	case <-timer.C:
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
func (c *Cache) HostInfos(ip net.IP) []string {
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
		vendor := c.vendorByIP(ip)
		if vendor != "" {
			infos = append(infos, vendor)
		}
	}

	return append(hostnames, infos...)
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

func commandAvailable(executable string, goos string) bool {
	if goos != "" && runtime.GOOS != goos {
		return false
	}

	_, err := exec.LookPath(executable)

	return err == nil
}

func fileAvailable(filename string, goos string) bool {
	if goos != "" && runtime.GOOS != goos {
		return false
	}

	_, err := os.Stat(filename)

	return err == nil
}

func readOutput(timeout time.Duration, name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	return output
}

func readFileIfPossible(filename string) []byte {
	content, _ := os.ReadFile(filename) // nolint:gosec

	return content
}
