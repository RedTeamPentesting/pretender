package hostinfo

import (
	"net"
	"runtime"
	"strings"
)

var (
	linuxArpPseudoFile          = "/proc/net/arp"
	windowsArpCommandAvailable  = commandAvailable("arp", osWindows)
	linuxArpPseudoFileAvailable = fileAvailable(linuxArpPseudoFile, osLinux)
)

func getMACFromLinuxARP(ip net.IP) net.HardwareAddr {
	if !linuxArpPseudoFileAvailable || runtime.GOOS != osLinux {
		return nil
	}

	if testMode {
		return getMACFromLinuxARPContent(ip, readFileIfPossible("testdata/unified/linux_proc_net_arp"))
	}

	return getMACFromLinuxARPContent(ip, readFileIfPossible(linuxArpPseudoFile))
}

func getMACFromLinuxARPContent(ip net.IP, arpContent []byte) net.HardwareAddr {
	if ip == nil || arpContent == nil {
		return nil
	}

	for _, line := range strings.Split(string(arpContent), "\n") {
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

func getIPFromLinuxARP(mac net.HardwareAddr) net.IP {
	if !linuxArpPseudoFileAvailable || runtime.GOOS != osLinux {
		return nil
	}

	if testMode {
		return getIPFromLinuxARPContent(mac, readFileIfPossible("testdata/unified/linux_proc_net_arp"))
	}

	return getIPFromLinuxARPContent(mac, readFileIfPossible(linuxArpPseudoFile))
}

func getIPFromLinuxARPContent(mac net.HardwareAddr, arpContent []byte) net.IP {
	if mac == nil || arpContent == nil {
		return nil
	}

	for _, line := range strings.Split(string(arpContent), "\n") {
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

func getMACFromWindowsARP(ip net.IP) net.HardwareAddr {
	if !windowsArpCommandAvailable || runtime.GOOS != osWindows {
		return nil
	}

	if testMode {
		return getMACFromWindowsARPOutput(ip, readFileIfPossible("testdata/unified/windows_arp"))
	}

	return getMACFromWindowsARPOutput(ip, readOutput(execTimeoutWindows,
		"arp", "-a"))
}

// nolint:gomnd
func getMACFromWindowsARPOutput(ip net.IP, arpOutput []byte) net.HardwareAddr {
	if ip == nil || arpOutput == nil {
		return nil
	}

	skip := false

	for _, line := range strings.Split(string(arpOutput), "\n") {
		if len(line) == 0 {
			continue
		}

		// interface section header
		if line[0] != ' ' {
			// skip next line because it's a table header
			skip = true

			continue
		}

		if skip {
			// skip table header
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

		mac, err := net.ParseMAC(fields[1])
		if err == nil {
			return mac
		}
	}

	return nil
}

func getIPFromWindowsARP(mac net.HardwareAddr) net.IP {
	if !windowsArpCommandAvailable || runtime.GOOS != osWindows {
		return nil
	}

	if testMode {
		return getIPFromWindowsARPOutput(mac, readFileIfPossible("testdata/unified/windows_arp"))
	}

	return getIPFromWindowsARPOutput(mac, readOutput(execTimeoutWindows,
		"arp", "-a"))
}

func getIPFromWindowsARPOutput(mac net.HardwareAddr, arpOutput []byte) net.IP {
	skip := false

	for _, line := range strings.Split(string(arpOutput), "\n") {
		if len(line) == 0 {
			continue
		}

		// interface section header
		if line[0] != ' ' {
			// skip next line because it's a table header
			skip = true

			continue
		}

		if skip {
			// skip table header
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
		return getIPFromWindowsARP(mac)
	}

	return getIPFromLinuxARP(mac)
}

func getMACFromOS(ip net.IP) net.HardwareAddr {
	switch runtime.GOOS {
	case osLinux:
		if ip.To4() == nil {
			return getMACFromLinuxIPNeighbor(ip)
		}

		return getMACFromLinuxARP(ip)
	case osWindows:
		if ip.To4() == nil {
			return getMACFromWindowsNetshShowNeighbors(ip)
		}

		return getMACFromWindowsARP(ip)
	default:
		return nil
	}
}
