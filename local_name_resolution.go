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
func RunNetBIOSResponder(ctx context.Context, logger *Logger, config Config) error { // nolint:cyclop
	var wg sync.WaitGroup

	addrs, err := config.Interface.Addrs()
	if err != nil {
		return fmt.Errorf("listing addresses on interface %q: %w", config.Interface.Name, err)
	}

	activeListenAddresses := map[string]bool{}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			return fmt.Errorf("cannot extract IP address from network")
		}

		if ip.IP.To4() == nil {
			continue
		}

		listenIP, err := subnetBroadcastListenIP(ip)
		if err != nil {
			return fmt.Errorf("calculate subnet broadcast IP: %w", err)
		}

		if activeListenAddresses[listenIP.String()] {
			continue
		}

		listenAddr := &net.UDPAddr{IP: listenIP, Port: netBIOSPort}

		conn, err := net.ListenUDP("udp4", listenAddr)
		if err != nil {
			errStr := err.Error()
			if runtime.GOOS == osWindows && strings.Contains(err.Error(), "Only one usage of each socket address") {
				errStr += " (try disabling NetBIOS: Interface Status->"
				errStr += "Properties->TCP/IPv4->Advanced->WINS->Disable NetBIOS over TCP/IP)"
			}

			return fmt.Errorf(errStr)
		}

		activeListenAddresses[listenIP.String()] = true

		wg.Add(1)

		go func() {
			defer wg.Done()
			defer conn.Close() // nolint:errcheck

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

func decodeNetBIOSEncoding(netBIOSName string) string {
	netBIOSName = normalizedName(netBIOSName)

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

	return decodedName
}

func decodeNetBIOSHostname(netBIOSName string) string {
	decodedName := decodeNetBIOSEncoding(netBIOSName)
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

// The following constants hold the names of the NetBIOS suffixes
// (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/
// 6dbf0972-bb15-4f29-afeb-baaae98416ed#Appendix_A_2).
const (
	NetBIOSSuffixWorkstationService                 = "Workstation Name"
	NetBIOSSuffixWindowsMessengerService            = "Messenger Service"
	NetBIOSSuffixRemoteAccessServer                 = "Remote Access Server"
	NetBIOSSuffixNetDDEService                      = "NetDDE Service"
	NetBIOSSuffixFileService                        = "File Service"
	NetBIOSSuffixRemoteAccessServiceClient          = "Remote Access Client"
	NetBIOSSuffixMSExchangeServerInterchange        = "MS Exchange Service Interchange"
	NetBIOSSuffixMSExchangeStore                    = "MS Exchange Store"
	NetBIOSSuffixMSExchangeDirectory                = "MS Exchange Directory"
	NetBIOSSuffixLotusNotesServerService            = "Lotus Notes Server"
	NetBIOSSuffixLotusNotes                         = "Lotus Notes"
	NetBIOSSuffixModemSharingServerService          = "Modem Sharing Server"
	NetBIOSSuffixModemSharingClientService          = "Modem Sharing Client"
	NetBIOSSuffixSMSClientsRemoteControl            = "SMS Clients Remote Control"
	NetBIOSSuffixSMSAdministratorsRemoteControlTool = "SMS Admin Remote Control Tool"
	NetBIOSSuffixSMSClientsRemoteChat               = "SMS Clients Remote Chat"
	NetBIOSSuffixSMSClientsRemoteTransfer           = "SMS Clients Remote Transfer"
	NetBIOSSuffixDECPathworksTCPIPService           = "DEC Pathworks TCPIP Service"
	NetBIOSSuffixMacAfeeAntivirus                   = "McAfee Antivirus"
	NetBIOSSuffixMSExchangeMTA                      = "MS Exchange MTA"
	NetBIOSSuffixMSExchangeIMC                      = "MS Exchange IMC"
	NetBIOSSuffixNetworkMonitorAgent                = "Network Monitor Agent"
	NetBIOSSuffixNetworkMonitorApplication          = "Network Monitor Application"
	NetBIOSSuffixDomainMasterBrowser                = "Primary DC"
	NetBIOSSuffixMasterBrowser                      = "Master Browser"
	NetBIOSSuffixDomainControllers                  = "Domain Controllers"
	NetBIOSSuffixBrowserServiceElections            = "Browser Server Elections"
	NetBIOSSuffixMSBrowse                           = "MSBROWSE Master Browser"
)

func decodeNetBIOSSuffix(netBIOSName string) string { // nolint:gocyclo,cyclop
	const decodedBIOSNameSize = 16

	decodedName := decodeNetBIOSEncoding(netBIOSName)
	if len(decodedName) != decodedBIOSNameSize {
		return "No Suffix"
	}

	// nolint:gomnd
	switch suffix := decodedName[decodedBIOSNameSize-1]; suffix {
	case 0x00:
		return NetBIOSSuffixWorkstationService
	case 0x01:
		if decodedName[decodedBIOSNameSize-2] == 0x02 {
			return NetBIOSSuffixMSBrowse
		}

		return NetBIOSSuffixWindowsMessengerService
	case 0x03:
		return NetBIOSSuffixWindowsMessengerService
	case 0x06:
		return NetBIOSSuffixRemoteAccessServer
	case 0x1C:
		return NetBIOSSuffixDomainControllers
	case 0x1D:
		return NetBIOSSuffixMasterBrowser
	case 0x1E:
		return NetBIOSSuffixBrowserServiceElections
	case 0x1F:
		return NetBIOSSuffixNetDDEService
	case 0x20:
		return NetBIOSSuffixFileService
	case 0x21:
		return NetBIOSSuffixRemoteAccessServiceClient
	case 0x22:
		return NetBIOSSuffixMSExchangeServerInterchange
	case 0x23:
		return NetBIOSSuffixMSExchangeStore
	case 0x24:
		return NetBIOSSuffixMSExchangeDirectory
	case 0x2B:
		return NetBIOSSuffixLotusNotesServerService
	case 0x2F, 0x33:
		return NetBIOSSuffixLotusNotes
	case 0x30:
		return NetBIOSSuffixModemSharingServerService
	case 0x31:
		return NetBIOSSuffixModemSharingClientService
	case 0x1B:
		return NetBIOSSuffixDomainMasterBrowser
	case 0x42:
		return NetBIOSSuffixMacAfeeAntivirus
	case 0x43:
		return NetBIOSSuffixSMSClientsRemoteControl
	case 0x44:
		return NetBIOSSuffixSMSAdministratorsRemoteControlTool
	case 0x45:
		return NetBIOSSuffixSMSClientsRemoteChat
	case 0x46:
		return NetBIOSSuffixSMSClientsRemoteTransfer
	case 0x4C, 0x52:
		return NetBIOSSuffixDECPathworksTCPIPService
	case 0x87:
		return NetBIOSSuffixMSExchangeMTA
	case 0x6A:
		return NetBIOSSuffixMSExchangeIMC
	case 0xBE:
		return NetBIOSSuffixNetworkMonitorAgent
	case 0xBF:
		return NetBIOSSuffixNetworkMonitorApplication
	default:
		return fmt.Sprintf("Suffix 0x%02x", suffix)
	}
}

func encodeNetBIOSLocator(ip net.IP) string {
	return "0000" + hex.EncodeToString(ip.To4())
}

// RunMDNSResponder creates a listener for mDNS requests.
func RunMDNSResponder(ctx context.Context, logger *Logger, config Config) error { // nolint:dupl
	errGroup, ctx := errgroup.WithContext(ctx)

	if hasIPv4Address(config.Interface) {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{IP: net.ParseIP(mDNSMulticastIPv4), Port: mDNSPort}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			defer conn.Close() // nolint:errcheck

			logger.Infof("listening via UDP on %s", listenAddr)

			err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
			if err != nil {
				return err
			}

			return nil
		})
	}

	if hasIPv6Address(config.Interface) && !config.NoIPv6LNR {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{
				IP:   net.ParseIP(mDNSMulticastIPv6),
				Port: mDNSPort,
				Zone: config.Interface.Name,
			}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			defer conn.Close() // nolint:errcheck

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

	if hasIPv4Address(config.Interface) {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{IP: net.ParseIP(llmnrMulticastIPv4), Port: llmnrPort}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			defer conn.Close() // nolint:errcheck

			logger.Infof("listening via UDP on %s", listenAddr)

			err = RunDNSHandlerOnUDPConnection(ctx, conn, logger, config)
			if err != nil {
				return err
			}

			return nil
		})
	}

	if hasIPv6Address(config.Interface) && !config.NoIPv6LNR {
		errGroup.Go(func() error {
			listenAddr := &net.UDPAddr{
				IP:   net.ParseIP(llmnrMulticastIPv6),
				Port: llmnrPort,
				Zone: config.Interface.Name,
			}

			conn, err := ListenUDPMulticast(config.Interface, listenAddr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			defer conn.Close() // nolint:errcheck

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

func hasIPv4Address(iface *net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip.IP.To4() != nil {
			return true
		}
	}

	return false
}
