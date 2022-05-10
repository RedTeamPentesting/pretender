package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/sync/errgroup"
)

const (
	netBIOSPort = 137

	mDNSMulticastIPv4 = "224.0.0.251"
	mDNSMulticastIPv6 = "ff02::fb"
	mDNSPort          = 5353

	llmnrMulticastIPv4 = "224.0.0.252"
	llmnrMulticastIPv6 = "ff02::1:3"
	llmnrPort          = 5355
)

// RunNetBIOSResponder creates a listener for NetBIOS name resolution requests.
func RunNetBIOSResponder(ctx context.Context, logger *Logger, config Config) error {
	var wg sync.WaitGroup

	addrs, err := config.Interface.Addrs()
	if err != nil {
		return fmt.Errorf("listening addresses on interface %q: %w", config.Interface.Name, err)
	}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			return fmt.Errorf("cannot extract IP address from network")
		}

		if ip.IP.To4() == nil {
			continue
		}

		wg.Add(1)

		go func() {
			defer wg.Done()

			listenIP, err := subnetBroadcastListenIP(ip)
			if err != nil {
				logger.Errorf("calculate subnet broadcast IP: %w", err)

				return
			}

			listenAddr := &net.UDPAddr{IP: listenIP, Port: netBIOSPort}

			conn, err := net.ListenUDP("udp4", listenAddr)
			if err != nil {
				logLine := "listen udp: " + err.Error()
				if runtime.GOOS == osWindows && strings.Contains(err.Error(), "Only one usage of each socket address") {
					logLine += " (try disabling NetBIOS: Interface Status->"
					logLine += "Properties->TCP/IPv4->Advanced->WINS->Disable NetBIOS over TCP/IP)"
				}

				logger.Errorf(logLine)

				return
			}

			logger.Infof("listening via UDP on %s", listenAddr)

			err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
			if err != nil {
				logger.Errorf(err.Error())
			}
		}()
	}

	wg.Wait()

	return nil
}

// subnetBroadcastListenIP returns the IP to listen on for NetBIOS broadcasts
// which is the highest IP in the subnet for Linux and the regular IP for
// Windows.
func subnetBroadcastListenIP(ip *net.IPNet) (net.IP, error) {
	ipv4 := ip.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid argument: IPv6 instead of IPv4")
	}

	if runtime.GOOS == osWindows {
		return ipv4, nil
	}

	rawIP := binary.BigEndian.Uint32(ipv4)
	rawMask := binary.BigEndian.Uint32(net.IP(ip.Mask).To4())
	broadcastIP := make(net.IP, len(ipv4))

	binary.BigEndian.PutUint32(broadcastIP, rawIP|^rawMask)

	return broadcastIP, nil
}

func decodeNetBIOSHostname(netBIOSName string) string {
	netBIOSName = strings.TrimSuffix(netBIOSName, ".")

	if len(netBIOSName)%2 != 0 {
		return netBIOSName
	}

	decodedName := ""

	for i := 0; i < len(netBIOSName); i += 2 {
		higher := netBIOSName[i] - 'A'
		lower := netBIOSName[i+1] - 'A'

		full := higher<<4 | lower // nolint:gomnd
		decodedName += string(full)
	}

	if decodedName == "" {
		return ""
	}

	for {
		suffix := decodedName[len(decodedName)-1]

		if unicode.IsGraphic(rune(suffix)) {
			break
		}

		decodedName = strings.TrimRight(decodedName, string(suffix))
	}

	return strings.TrimSpace(decodedName)
}

func encodeNetBIOSLocator(ip net.IP) string {
	return "0000" + hex.EncodeToString(ip.To4())
}

// RunMDNSResponder creates a listener for mDNS requests.
func RunMDNSResponder(ctx context.Context, logger *Logger, config Config) error { // nolint:dupl
	errGroup, ctx := errgroup.WithContext(ctx)

	errGroup.Go(func() error {
		listenAddr := &net.UDPAddr{IP: net.ParseIP(mDNSMulticastIPv4), Port: mDNSPort}

		conn, err := ListenUDPMulticast(config.Interface, listenAddr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		logger.Infof("listening via UDP on %s", listenAddr)

		err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
		if err != nil {
			return err
		}

		return nil
	})

	if hasIPv6Address(config.Interface) && !config.NoIPv6LNR {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{IP: net.ParseIP(mDNSMulticastIPv6), Port: mDNSPort}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			logger.Infof("listening via UDP on %s", listenAddr)

			err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
			if err != nil {
				return err
			}

			return nil
		})
	}

	return errGroup.Wait()
}

// RunLLMNRResponder creates a listener for LLMNR requests.
func RunLLMNRResponder(ctx context.Context, logger *Logger, config Config) error { // nolint:dupl
	errGroup, ctx := errgroup.WithContext(ctx)

	errGroup.Go(func() error {
		listenAddr := &net.UDPAddr{IP: net.ParseIP(llmnrMulticastIPv4), Port: llmnrPort}

		conn, err := ListenUDPMulticast(config.Interface, listenAddr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		logger.Infof("listening via UDP on %s", listenAddr)

		err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
		if err != nil {
			return err
		}

		return nil
	})

	if hasIPv6Address(config.Interface) && !config.NoIPv6LNR {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{IP: net.ParseIP(llmnrMulticastIPv6), Port: llmnrPort}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			logger.Infof("listening via UDP on %s", listenAddr)

			err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
			if err != nil {
				return err
			}

			return nil
		})
	}

	return errGroup.Wait()
}

func hasIPv6Address(iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip.IP.To4() == nil {
			return true
		}
	}

	return false
}
