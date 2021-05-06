package main

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/net/ipv6"
)

// ListenUDPMulticast listens on a multicast group in a way that is supported on
// Unix and Windows for both IPv4 and IPv6.
func ListenUDPMulticast(iface *net.Interface, multicastGroup *net.UDPAddr) (net.PacketConn, error) {
	if multicastGroup.IP.To4() != nil {
		return net.ListenMulticastUDP("udp", iface, multicastGroup)
	}

	if runtime.GOOS != osWindows {
		return net.ListenMulticastUDP("udp6", iface, &net.UDPAddr{
			IP:   multicastGroup.IP,
			Port: multicastGroup.Port,
			Zone: multicastGroup.Zone,
		})
	}

	listenAddr := &net.UDPAddr{IP: multicastGroup.IP, Port: multicastGroup.Port}

	conn, err := net.ListenPacket("udp6", listenAddr.String())
	if err != nil {
		return nil, err
	}

	packetConn := ipv6.NewPacketConn(conn)

	err = packetConn.JoinGroup(iface, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("join multicast group %s: %w", listenAddr.IP, err)
	}

	return conn, nil
}
