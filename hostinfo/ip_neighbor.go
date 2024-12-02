package hostinfo

import (
	"bufio"
	"bytes"
	"net"
	"runtime"
	"strings"
)

var linuxIPCommandAvailable = commandAvailable("ip", osLinux)

func getMACFromLinuxIPNeighbor(ip net.IP) net.HardwareAddr {
	if !linuxIPCommandAvailable || runtime.GOOS != osLinux {
		return nil
	}

	if testMode {
		return getMacFromLinuxIPNeighborOutput(ip, readFileIfPossible("testdata/unified/linux_ip_neighbor"))
	}

	return getMacFromLinuxIPNeighborOutput(ip, readOutput(execTimeoutLinux, "ip", "neighbor"))
}

func getMacFromLinuxIPNeighborOutput(ip net.IP, ipNeighOutput []byte) net.HardwareAddr {
	if ip == nil || ipNeighOutput == nil {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(ipNeighOutput))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " ", 6) //nolint:mnd
		if len(parts) < 6 {                             //nolint:mnd
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
