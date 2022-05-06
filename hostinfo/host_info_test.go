package hostinfo

import (
	"net"
	"os"
	"strings"
	"testing"
)

// nolint:gochecknoinits
func init() {
	testMode = true

	vendorsContent, err := os.ReadFile("testdata/unified/mac-vendors.txt")
	if err != nil {
		panic(err)
	}

	macVendorsFile = string(vendorsContent)
}

func TestCacheHostInfos(t *testing.T) {
	c := NewCache()

	ipv6 := mustParseIP(t, "fe80::a00:27ff:fe56:c24c")
	c.resolvedHostnames[ipv6.String()] = nil // unresolvable

	ipv4 := mustParseIP(t, "192.168.56.101")
	c.resolvedHostnames[ipv6.String()] = nil // unresolvable

	c.toMAC(ipv4)

	c.SaveMACFromIP(ipv6, nil)

	c.AddHostnamesForIP(ipv4, []string{"foo"})
	c.AddHostnamesForIP(ipv6, []string{"bar"})

	assertContainsExactly(t, c.HostInfos(ipv6), "foo", "bar", ipv4.String())

	otherIPv6 := mustParseIP(t, "fe80::800:27ff:fe00:0")
	c.resolvedHostnames[otherIPv6.String()] = nil // unresolvable

	// this IPv4 has the same MAC as otherIPv6
	c.resolvedHostnames[mustParseIP(t, "192.168.56.100").String()] = nil // unresolvable

	assertContainsExactly(t, c.HostInfos(otherIPv6),
		"192.168.56.100", "test")
}

func TestCacheSaveMACFromIP(t *testing.T) {
	c := NewCache()

	ipv4 := mustParseIP(t, "192.168.56.101")
	c.toMAC(ipv4)

	// ipv6 contains the EUI-64 encoded MAC that matches the ipv4 address above
	ipv6 := mustParseIP(t, "fe80::a00:27ff:fe56:c24c")

	c.SaveMACFromIP(ipv6, nil)

	resolvedIPv4 := c.toIPv4(ipv6)
	if !resolvedIPv4.Equal(ipv4) {
		t.Errorf("IPv6 resolved to %s instead of %s", resolvedIPv4, ipv4)
	}
}

func TestCacheHostnames(t *testing.T) {
	c := NewCache()

	ipv4 := mustParseIP(t, "192.168.56.101")
	ipv6 := mustParseIP(t, "fe80::d422:2ab:8bf4:7381")

	// simulate previous lookup
	c.resolvedHostnames[ipv4.String()] = []string{"a"}
	c.resolvedHostnames[ipv6.String()] = []string{"b"}
	// lookup macs
	c.toMAC(ipv4)
	c.toMAC(ipv6)

	c.AddHostnamesForIP(ipv4, []string{"c"})
	c.AddHostnamesForIP(ipv4, []string{"c"})
	c.AddHostnamesForIP(ipv4, []string{"a"})

	c.AddHostnamesForIP(ipv6, []string{"d"})

	assertContainsExactly(t, c.hostnames(ipv4), "a", "b", "c", "d")
	assertContainsExactly(t, c.hostnames(ipv6), "a", "b", "c", "d")
}

func TestCacheToIPv4Ipv6(t *testing.T) {
	c := NewCache()

	ipv4 := mustParseIP(t, "192.168.56.101")
	ipv6 := mustParseIP(t, "fe80::d422:2ab:8bf4:7381")

	resolvedIPv4 := c.toIPv4(ipv6)
	if !resolvedIPv4.Equal(ipv4) {
		t.Errorf("resolved %s to %s instead of %s", ipv6, resolvedIPv4, ipv4)
	}

	resolvedIPv6 := c.toIPv6(ipv4)
	if !resolvedIPv6.Equal(ipv6) {
		t.Errorf("resolved %s to %s instead of %s", ipv4, resolvedIPv6, ipv6)
	}
}

func TestCacheMACResolution(t *testing.T) {
	c := NewCache()

	assertVendor(t, c, "08:00:27:00:00:01", "A")
	assertVendor(t, c, "08:00:27:c2:e0:27", "A")
	assertVendor(t, c, "00:00:00:00:00:00", "")
	assertVendor(t, c, "52:54:00:52:54:00", "B")
	assertVendor(t, c, "0a:00:27:00:00:00", "test")
	assertVendor(t, c, "ff:ff:ff:ff:ff:ff", "C")
	assertVendor(t, c, "FF:FF:FF:FF:FF:FF", "C")
}

func assertVendor(tb testing.TB, c *Cache, macString string, vendor string) {
	tb.Helper()

	mac, err := net.ParseMAC(macString)
	if err != nil {
		tb.Errorf("parse MAC %q: %v", macString, err)

		return
	}

	v := c.vendorByMAC(mac)
	if v != vendor {
		tb.Errorf("resolved MAC %s to vendor %q instead of %q", macString, v, vendor)
	}
}

func testGetMac(tb testing.TB, testOutputFileName string,
	resolver func(net.IP, []byte) net.HardwareAddr, testCases []macIPTestCase,
) {
	tb.Helper()

	content, err := os.ReadFile(testOutputFileName) // nolint:gosec
	if err != nil {
		tb.Fatalf("read proc file: %v", err)
	}

	for i, testCase := range testCases {
		ip := net.ParseIP(testCase.ip)
		if ip == nil && testCase.ip != "" {
			tb.Errorf("invalid input IP in testcase %d: %s", i, testCase.ip)
		}

		expectedMAC, err := net.ParseMAC(testCase.mac)
		if err != nil && testCase.mac != "" {
			tb.Errorf("invalid exepcted output MAC in testcase %d: %s", i, testCase.mac)
		}

		mac := resolver(ip, content)
		if mac.String() != expectedMAC.String() {
			tb.Errorf("get MAC of IP %s (%s): got %s instead of %s",
				ip, strings.TrimPrefix(testOutputFileName, "testdata/"), mac, expectedMAC)
		}
	}
}

func testGetIP(tb testing.TB, testOutputFileName string,
	resolver func(net.HardwareAddr, []byte) net.IP, testCases []macIPTestCase,
) {
	tb.Helper()

	content, err := os.ReadFile(testOutputFileName) // nolint:gosec
	if err != nil {
		tb.Fatalf("read proc file: %v", err)
	}

	for i, testCase := range testCases {
		mac, err := net.ParseMAC(testCase.mac)
		if err != nil && testCase.mac != "" {
			tb.Errorf("invalid exepcted output MAC in testcase %d: %s", i, testCase.mac)
		}

		expectedIP := net.ParseIP(testCase.ip)
		if expectedIP == nil && testCase.ip != "" {
			tb.Errorf("invalid input IP in testcase %d: %s", i, testCase.ip)
		}

		ip := resolver(mac, content)
		if ip.String() != expectedIP.String() {
			tb.Errorf("get IP of MAC %s (%s): got %s instead of %s",
				mac, strings.TrimPrefix(testOutputFileName, "testdata/"), ip, expectedIP)
		}
	}
}

func assertContainsExactly(tb testing.TB, got []string, required ...string) {
	tb.Helper()

	if len(got) != len(required) {
		tb.Errorf("got %+v elements instead of %+v", got, required)
	}

	for _, needle := range required {
		if !containsString(got, needle) {
			tb.Errorf("missing entry: %s", needle)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, element := range haystack {
		if element == needle {
			return true
		}
	}

	return false
}

func mustParseIP(tb testing.TB, ip string) net.IP {
	tb.Helper()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		tb.Fatalf("cannot parse IP %s", ip)
	}

	return parsedIP
}
