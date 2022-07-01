<p align="center">
  <h1 align="center"><b>pretender</b></h1>
  <p align="center"><i>Your MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover<br>as well as mDNS, LLMNR and NetBIOS-NS spoofing</i></p>
  <p align="center">
    <a href="https://github.com/RedTeamPentesting/pretender/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/RedTeamPentesting/pretender.svg?style=for-the-badge"></a>
    <a href="https://github.com/RedTeamPentesting/pretender/actions?workflow=Check"><img alt="GitHub Action: Check" src="https://img.shields.io/github/workflow/status/RedTeamPentesting/pretender/Check/main?style=for-the-badge"></a>
    <a href="/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
    <a href="https://goreportcard.com/report/github.com/RedTeamPentesting/pretender"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/RedTeamPentesting/pretender?style=for-the-badge"></a>
  </p>
</p>

---

`pretender` is a tool developed by RedTeam Pentesting to obtain
machine-in-the-middle positions via spoofed local name resolution and DHCPv6 DNS
takeover attacks. `pretender` primarily targets Windows hosts, as it is intended
to be used for relaying attacks but can be deployed on Linux, Windows and all
other platforms Go supports. It can also answer with arbitrary IPs for
situations where the relaying tool runs on a different host than `pretender`.

Read our [blog
post](https://blog.redteam-pentesting.de/2022/introducing-pretender/) for more
information about DHCPv6 DNS takeover, local name resolution spoofing and relay
attacks.

---

## Usage

To get a feel for the situation in the local network, `pretender` can be started
in `--dry` mode where it only logs incoming queries and does not answer any of
them:

```sh
pretender -i eth0 --dry
pretender -i eth0 --dry --no-ra # without router advertisements
```

To perform local name resolution spoofing via mDNS, LLMNR and NetBIOS-NS as well
as a DHCPv6 DNS takeover with router advertisements, simply run `pretender` like
this:

```sh
pretender -i eth0
```

You can disable certain attacks with `--no-dhcp-dns` (disabled DHCPv6, DNS and
router advertisements), `--no-lnr` (disabled mDNS, LLMNR and NetBIOS-NS),
`--no-mdns`, `--no-llmnr`, `--no-netbios` and `--no-ra`.

If `ntlmrelayx.py` runs on a different host (say `10.0.0.10`/`fe80::5`), run
`pretender` like this:

```sh
pretender -i eth0 -4 10.0.0.10 -6 fe80::5
```

Pretender can be setup to only respond to queries for certain domains (or all
_but_ certain domains) and it can perform the spoofing attacks only for certain
hosts (or all _but_ certain hosts). Referencing hosts by hostname relies on the
name resolution of the host that runs `pretender`. See the following example:

```sh
pretender -i eth0 --spoof example.com --dont-spoof-for 10.0.0.3,host1.corp,fe80::f --ignore-nofqdn
```

For more information, run `pretender --help`.

---

## Tips

- Make sure to enable IPv6 support in `ntlmrelayx.py` with the `-6` flag
- Pretender can be configured to stop after a certain time period for situations
  where it cannot be aborted manually (`--stop-after` and
  `main.vendorStopAfter`)
- Host info lookup (which relies on the ARP table, IP neighbours and reverse
  lookups) can be disabled with `--no-host-info` or `main.vendorNoHostInfo`
- If you are not sure which interface to choose (especially on Windows), list
  all interfaces with names and addresses using `--interfaces`
- If you want to exclude hosts from local name resolution spoofing, make sure to
  also exclude their IPv6 addresses or use `--no-ipv6-lnr`/`main.vendorNoIPv6LNR`
- DHCPv6 messages usually contain a FQDN option (which can also sometimes
  contain a hostname which is not a FQDN). This option is used to filter out
  messages by hostname (`--spoof-for`/`--dont-spoof-for`). You can decide what
  to do with DHCPv6 messages without FQDN option by setting or omitting
  `--ignore-nofqdn`
- Depending on the build configuration, either the operating system resolver
  (`CGO_ENABLED=1`) or a Go implementation (`CGO_ENABLED=0`) is used. This can
  be important for host info collection because the OS resolver may support
  local name resolution and the Go implementation does not, unless a stub
  resolver is used.
- The host info functionality is currently only available for Windows and Linux.
- A custom MAC address vendor list can be compiled into the binary by replacing
  the default list `hostinfo/mac-vendors.txt`. Only lines with MAC prefixes in
  the following format are recognized: `FF:FF:FF<tab>VendorID<tab>Vendor`.
- When conducting a Kerberos relay attack where `krbrelayx.py` runs on a
  different host than pretender (relay IPv4 address points to different host
  that runs `krbrelayx.py`), the host running `krbrelayx.py` will also need to
  run pretender in order to receive and deny the Dynamic Update query sent to
  the relay IPv4 address.

---

## Building and Vendoring

Pretender can be build as follows:

```sh
go build
```

Pretender can also be compiled with pre-configured settings. For this, the
`ldflags` have to be modified like this:

```sh
-ldflags '-X main.vendorInterface=eth1'
```

For example, Pretender can be built for Windows with a specific default
interface, without colored output and with a relay IPv4 address configured:

```
GOOS=windows go build -trimpath -ldflags '-X "main.vendorInterface=Ethernet 2" -X main.vendorNoColor=true -X main.vendorRelayIPv4=10.0.0.10'
```

Full list of vendoring options (see `defaults.go` or `pretender --help` for
detailed information):

```
vendorInterface
vendorRelayIPv4
vendorRelayIPv6
vendorSOAHostname
vendorNoDHCPv6DNSTakeover
vendorNoDHCPv6
vendorNoDNS
vendorNoMDNS
vendorNoNetBIOS
vendorNoLLMNR
vendorNoLocalNameResolution
vendorNoRA
vendorNoIPv6LNR
vendorSpoof
vendorDontSpoof
vendorSpoofFor
vendorDontSpoofFor
vendorSpoofTypes
vendorIgnoreDHCPv6NoFQDN
vendorDryMode
vendorTTL
vendorLeaseLifetime
vendorRARouterLifetime
vendorRAPeriod
vendorStopAfter
vendorVerbose
vendorNoColor
vendorNoTimestamps
vendorLogFileName
vendorNoHostInfo
vendorHideIgnored
vendorRedirectStderr
vendorListInterfaces
```
