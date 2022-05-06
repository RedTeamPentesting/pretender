package hostinfo

import "testing"

func TestGetMacFromWindowsNetshShowNeighborsOutput(t *testing.T) {
	testGetMac(t, "testdata/windows_netsh_show_neighbors", getMACFromWindowsNetshShowNeighborsOutput, []macIPTestCase{
		{ip: "", mac: ""},
		{ip: "127.0.0.1", mac: ""},
		{ip: "ff02::1", mac: "33-33-00-00-00-01"},
		{ip: "ff02::2", mac: "33-33-00-00-00-02"},
		{ip: "ff02::c", mac: "33-33-00-00-00-0c"},
		{ip: "ff02::16", mac: "33-33-00-00-00-16"},
		{ip: "ff02::fb", mac: "33-33-00-00-00-fb"},
		{ip: "ff02::1:2", mac: "33-33-00-01-00-02"},
		{ip: "ff02::1:3", mac: "33-33-00-01-00-03"},
		{ip: "ff02::1:ff49:f89a", mac: "33-33-ff-49-f8-9a"},
		{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08-00-27-7e-ca-64"},
		{ip: "ff02::1:ff04:792b", mac: "33-33-ff-04-79-2b"},
		{ip: "ff02::1:ff7e:ca64", mac: "33-33-ff-7e-ca-64"},
		{ip: "ff02::1:fff4:7381", mac: "33-33-ff-f4-73-81"},
	})

	testGetMac(t, "testdata/unified/windows_netsh_show_neighbors",
		getMACFromWindowsNetshShowNeighborsOutput, []macIPTestCase{
			{ip: "", mac: ""},
			{ip: "127.0.0.1", mac: ""},
			{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08-00-27-7e-ca-64"},
			{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08-00-27-7e-ca-64"},
			{ip: "fe80::a00:27ff:fe7e:ca64", mac: "08-00-27-7e-ca-64"},
			{ip: "fe80::d422:2ab:8bf4:7381", mac: "08-00-27-56-c2-4c"},
			{ip: "fe80::800:27ff:fe00:0", mac: "0a-00-27-00-00-00"},
		})
}
