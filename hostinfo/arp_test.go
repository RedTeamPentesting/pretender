package hostinfo

import (
	"testing"
)

type macIPTestCase struct {
	ip  string
	mac string
}

func TestGetMACFromLinuxArpContent(t *testing.T) {
	testGetMac(t, "testdata/linux_proc_net_arp", getMACFromLinuxARPContent, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
	})

	testGetMac(t, "testdata/unified/linux_proc_net_arp", getMACFromLinuxARPContent, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
	})
}

func TestGetIPFromLinuxARPContent(t *testing.T) {
	testGetIP(t, "testdata/linux_proc_net_arp", getIPFromLinuxARPContent, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "", mac: "01:01:01:01:01:01"},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
	})

	testGetIP(t, "testdata/unified/linux_proc_net_arp", getIPFromLinuxARPContent, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "", mac: "01:01:01:01:01:01"},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
	})
}

func TestGetMACFromWindowsARPOutput(t *testing.T) {
	testGetMac(t, "testdata/windows_arp", getMACFromWindowsARPOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "10.0.2.15", mac: ""},
		{ip: "192.168.56.101", mac: ""},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "10.0.2.255", mac: "ff:ff:ff:ff:ff:ff"},
		{ip: "192.168.56.9", mac: "08:00:27:7e:ca:64"},
		{ip: "239.255.255.250", mac: "01:00:5e:7f:ff:fa"},
	})

	testGetMac(t, "testdata/unified/windows_arp", getMACFromWindowsARPOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "10.0.2.15", mac: ""},
		{ip: "192.168.56.9", mac: ""},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
	})
}

func TestGetIPFromWindowsARPOutput(t *testing.T) {
	testGetIP(t, "testdata/windows_arp", getIPFromWindowsARPOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "", mac: "01:01:01:01:01:01"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "10.0.2.255", mac: "ff:ff:ff:ff:ff:ff"},
		{ip: "192.168.56.9", mac: "08:00:27:7e:ca:64"},
		{ip: "239.255.255.250", mac: "01:00:5e:7f:ff:fa"},
	})

	testGetIP(t, "testdata/unified/windows_arp", getIPFromWindowsARPOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "", mac: "01:01:01:01:01:01"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.101", mac: "08:00:27:56:c2:4c"},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
	})
}
