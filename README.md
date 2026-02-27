# Topsee / Tianshitong (天视通) IP Camera Discovery Tool

Discovers Topsee/Tianshitong IP cameras on your local network via UDP broadcast, then automatically enriches each discovered camera with full device info, stream URIs, and snapshot URIs via TCP SDK and ONVIF.

## Authors

- **Claude (Anthropic)** — protocol reverse engineering from `LinuxNetSDK_Release_x86_V22_20140529` binary analysis (disassembly of `libNetSDK.so`, frame structure, XML protocol, UDP response flow, ONVIF integration), full implementation
- **Contributors (silvije2)** — live packet capture validation, tcpdump-based protocol debugging, ONVIF script reference, firewall diagnostics, feature direction

---

## Features

- UDP broadcast discovery — finds all cameras on the subnet in seconds
- TCP SDK login (port 8091) — retrieves port config and validates credentials
- ONVIF query (port 80) — retrieves manufacturer, model, firmware, MAC, main/sub stream URIs, main/sub snapshot URIs
- Parallel enrichment — all cameras queried simultaneously
- Results sorted by IP address
- Summary table with main stream URI per camera

## Requirements

- Python 3.10+
- Linux (needs `sudo` to bind UDP port 3001)
- Cameras must be on the same subnet (or reachable via broadcast)

No third-party Python packages required — stdlib only.

## Firewall Setup

You must allow inbound UDP port 3001 before running. Do this once:

```bash
# iptables
sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT

# ufw
sudo ufw allow 3001/udp
```

To make the iptables rule persistent across reboots:
```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

## Usage

```bash
# Basic discovery (recommended)
sudo python3 topsee_udp_discover.py

# Bind to a specific interface if you have multiple NICs
sudo python3 topsee_udp_discover.py --iface 192.168.1.1

# Use subnet broadcast instead of 255.255.255.255
sudo python3 topsee_udp_discover.py --broadcast 192.168.1.255

# Longer timeout for slow or busy networks
sudo python3 topsee_udp_discover.py --timeout 15 --repeat 8

# UDP discovery only — skip TCP/ONVIF enrichment
sudo python3 topsee_udp_discover.py --no-tcp

# More parallel threads for large camera counts
sudo python3 topsee_udp_discover.py --threads 20

# Show raw XML responses for debugging
sudo python3 topsee_udp_discover.py --verbose
```

## Example Output

```
════════════════════════════════════════════════════════════════════
  192.168.2.22  —  NVS-DM36X-HD
────────────────────────────────────────────────────────────────────
  Serial Number     : 06D8877346xxxxxxA
  Manufacturer      : Tianshitong
  Firmware          : V1.0.0.7 2018-10-31 14:41:20
────────────────────────────────────────────────────────────────────
  MAC Address       : 00:87:d8:xx:xx:xx
  IP Address        : 192.168.1.10
  Netmask           : 255.255.255.0
  Gateway           : 192.168.1.1
  DHCP              : disabled
────────────────────────────────────────────────────────────────────
  RTSP Port         : 554
  SDK/PTZ Port      : 8091
  Web/ONVIF Port    : 80
────────────────────────────────────────────────────────────────────
  Main Stream       : rtsp://192.168.1.10:554/mpeg4
  Sub Stream        : rtsp://192.168.1.10:554/mpeg4cif
  Main Snapshot     : http://192.168.1.10/cgi-bin/snapshot.cgi?stream=0
  Sub Snapshot      : http://192.168.1.10/cgi-bin/snapshot.cgi?stream=1
────────────────────────────────────────────────────────────────────
  TCP/ONVIF Login   : admin / 123456
  Device Accounts   :
    admin            / 123456           [Enable]
```

## Protocol Details

### UDP Discovery (port 3001)

The camera listens on UDP port 3001 for a broadcast `SYSTEM_SEARCHIPC_MESSAGE` XML packet. When it receives one it broadcasts its response back to `255.255.255.255:3001` — **not** to the sender's source port. This means the discovery client must also bind to port 3001 (hence requiring `sudo`).

The response XML contains the full device identity, network config, user accounts, and stream port info.

### TCP SDK (port 8091)

Proprietary binary-framed XML protocol:

```
[58 91 58 51] [4-byte LE length] [GB2312 XML payload]
```

Login with `USER_AUTH_MESSAGE`, get a `Sessionid`, then query with `SYSTEM_CONFIG_GET_MESSAGE CMD 600` for `MediaStreamConfig`.

### ONVIF (port 80)

Standard ONVIF Profile S with WS-Security `PasswordDigest` authentication. Calls used:

| Call | Endpoint | Returns |
|------|----------|---------|
| `GetDeviceInformation` | `/onvif/device_service` | Manufacturer, Model, Firmware, Serial |
| `GetNetworkInterfaces` | `/onvif/device_service` | MAC, IP |
| `GetProfiles` | `/onvif/media_service` | Profile tokens |
| `GetStreamUri` | `/onvif/media_service` | RTSP stream URLs |
| `GetSnapshotUri` | `/onvif/media_service` | HTTP snapshot URLs |

### Other Ports

| Port | Protocol | Service |
|------|----------|---------|
| 80/tcp | HTTP/SOAP | ONVIF (gSOAP 2.8) |
| 554/tcp | RTSP | Live555 streaming |
| 8091/tcp | TCP | Proprietary SDK control channel |
| 3001/udp | UDP | Discovery broadcast |

## Legal & Ethical Use

**Use this tool only on networks and devices you own or have explicit written permission to administer.** Unauthorised scanning may violate applicable computer crime laws in your jurisdiction — including but not limited to the Computer Misuse Act (UK), the CFAA (US), and equivalent national legislation.

The authors are not responsible for any misuse of this tool.

### On the Legality of Reverse Engineering

The protocol implementation in this tool was derived entirely through reverse engineering of the Topsee/Tianshitong NetSDK shared library (`libNetSDK.so`). No proprietary source code is distributed here — only a clean-room reimplementation of the observed protocol behaviour.

**In the European Union** this is explicitly lawful. Article 6 of the EU Software Directive (Directive 2009/24/EC on the legal protection of computer programs) permits reverse engineering for the purpose of achieving interoperability with an independently created program, without requiring the rights holder's authorisation. Croatia, as an EU member state, implements this directive into national law. Contractual clauses in an SDK licence that purport to prohibit interoperability-motivated reverse engineering are unenforceable under EU law to the extent they conflict with Article 6.

Outside the EU, the legal position varies. In the US, the DMCA contains a similar interoperability exemption (17 U.S.C. § 1201(f)), though its scope is narrower. If you are outside the EU, consult local legal advice if in doubt.

### Security Note

The Topsee/Tianshitong UDP discovery protocol has a significant security weakness: **device credentials (usernames and passwords) are transmitted in plaintext inside the broadcast UDP response**, which is sent to `255.255.255.255` and is therefore visible to every host on the local network segment.

This means any device on the LAN can passively collect credentials from all cameras simply by listening on UDP port 3001 — no active scanning required.

**Recommended mitigations for network administrators:**
- Apply firewall rules to block UDP port 3001 from untrusted network segments
- Ensure cameras are on an isolated VLAN with restricted inter-VLAN routing
- Change default credentials on all devices
- Consider whether cameras need to be reachable from general user network segments at all

## Troubleshooting

**No cameras found**
- Check firewall: `sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT`
- Try subnet broadcast: `--broadcast 192.168.1.255`
- Increase timeout: `--timeout 15 --repeat 8`
- Verify cameras are on same subnet as your machine

**TCP/ONVIF enrichment fails**
- Check that port 8091 and 80 are reachable from your machine
- The tool tries `admin/` (blank), `admin/admin`, `admin/123456` plus any credentials found in the UDP response
- Use `--verbose` to see raw XML and diagnose auth issues

**`Permission denied` on startup**
- Must run with `sudo` — binding to port 3001 requires root on Linux
- Alternative: `sudo setcap cap_net_bind_service=+ep $(which python3)`
