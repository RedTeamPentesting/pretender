package hostinfo

import (
	"bufio"
	"bytes"
	"net"
	"runtime"
	"strings"
)

var windowsNetshCommandAvailable = commandAvailable("netsh", osWindows)

func getMACFromWindowsNetshShowNeighbors(ip net.IP) net.HardwareAddr {
	if !windowsNetshCommandAvailable || runtime.GOOS != osWindows {
		return nil
	}

	if testMode {
		return getMacFromLinuxIPNeighborOutput(ip, readFileIfPossible("testdata/unified/windows_netsh_show_neighbors"))
	}

	return getMACFromWindowsNetshShowNeighborsOutput(ip, readOutput(execTimeoutWindows,
		"netsh", "interface", "ipv6", "show", "neighbors"))
}

func getMACFromWindowsNetshShowNeighborsOutput(ip net.IP, netshOutput []byte) net.HardwareAddr {
	if ip == nil || netshOutput == nil {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(netshOutput))
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

		mac, err := net.ParseMAC(parts[1])
		if err == nil {
			return mac
		}
	}

	return nil
}
