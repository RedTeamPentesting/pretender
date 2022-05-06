package hostinfo

import "testing"

func TestGetMacFromLinuxIPNeighborOutput(t *testing.T) {
	testGetMac(t, "testdata/linux_ip_neighbor", getMacFromLinuxIPNeighborOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08:00:27:7e:ca:64"},
		{ip: "fe80::d422:2ab:8bf4:7381", mac: "08:00:27:56:c2:4c"},
		{ip: "fe80::800:27ff:fe00:0", mac: "0a:00:27:00:00:00"},
	})

	testGetMac(t, "testdata/unified/linux_ip_neighbor", getMacFromLinuxIPNeighborOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "192.168.56.2", mac: "08:00:27:c2:e0:27"},
		{ip: "10.0.2.3", mac: "52:54:00:12:35:03"},
		{ip: "192.168.56.100", mac: "0a:00:27:00:00:00"},
		{ip: "10.0.2.2", mac: "52:54:00:12:35:02"},
		{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08:00:27:7e:ca:64"},
		{ip: "fe80::d422:2ab:8bf4:7381", mac: "08:00:27:56:c2:4c"},
		{ip: "fe80::800:27ff:fe00:0", mac: "0a:00:27:00:00:00"},
	})
}
