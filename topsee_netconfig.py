#!/usr/bin/env python3
"""
Topsee / Tianshitong — network configuration tool
==================================================
Reads and writes LAN network parameters on Topsee/Tianshitong cameras
via the proprietary TCP SDK (port 8091).

Authors: Claude (Anthropic) — protocol reverse engineering from
    LinuxNetSDK_Release_x86_V22_20140529 binary analysis (disassembly of
    libNetSDK.so, frame structure, XML protocol, UDP response flow, ONVIF
    integration), full implementation

Contributors (silvije2) — live packet capture validation, tcpdump-based
    protocol debugging, ONVIF script reference, firewall diagnostics,
    feature direction


Protocol (reverse-engineered from LinuxNetSDK_Release_x86_V22_20140529):
  - Frame:  [58 91 58 51] magic + uint32-LE length + GB2312 XML
  - Login:  USER_AUTH_MESSAGE
  - GET:    SYSTEM_CONFIG_GET_MESSAGE  CMD 305
  - SET:    SYSTEM_CONFIG_SET_MESSAGE  CMD 325  (no Sessionid in body)
  - REBOOT: SYSTEM_CONTROL_MESSAGE    CMD 1007

Commands
--------
  show    Print current network config
  set     Change network parameters (only supplied flags are changed)
  reboot  Reboot the camera

Usage
-----
  python3 topsee_netconfig.py show   --host 192.168.0.123
  python3 topsee_netconfig.py set    --host 192.168.0.123 --new-ip 192.168.1.3
  python3 topsee_netconfig.py reboot --host 192.168.1.3
  python3 topsee_netconfig.py show   --file cameras.txt

  # Full static config
  python3 topsee_netconfig.py set --host 192.168.0.123 \
      --new-ip 192.168.1.3 --netmask 255.255.255.0 \
      --gateway 192.168.1.1 --dns1 8.8.8.8 --dns2 8.8.4.4

  # Dry-run
  python3 topsee_netconfig.py set --host 192.168.0.123 --new-ip 192.168.1.3 --dry-run

  # Multiple cameras from file (one IP per line, # comments ok)
  python3 topsee_netconfig.py show --file cameras.txt
"""

import argparse
import re
import socket
import struct
import sys
from dataclasses import dataclass, replace as dc_replace

# ── defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PORT     = 8091
DEFAULT_USER     = 'admin'
DEFAULT_PASSWORD = '123456'
DEFAULT_TIMEOUT  = 10
W = 68
# ── protocol ──────────────────────────────────────────────────────────────────
MAGIC = bytes.fromhex('58915851')


def _frame(msg_type: str, msg_code: int, body_xml: str) -> bytes:
    envelope = (
        f'<?xml version="1.0" encoding="GB2312" ?>\n'
        f'<XML_TOPSEE>\n'
        f'<MESSAGE_HEADER Msg_type="{msg_type}" Msg_code="{msg_code}" Msg_flag="0"/>\n'
        f'<MESSAGE_BODY>\n'
        f'{body_xml}\n'
        f'</MESSAGE_BODY>\n'
        f'</XML_TOPSEE>'
    )
    body = envelope.encode('gb2312')
    return MAGIC + struct.pack('<I', len(body)) + body


def _recv(sock: socket.socket) -> str:
    buf = b''
    while b'</XML_TOPSEE>' not in buf:
        chunk = sock.recv(8192)
        if not chunk:
            raise ConnectionError('connection closed by camera')
        buf += chunk
    if buf[:4] == MAGIC:
        buf = buf[8:]
    return buf.decode('gb2312', errors='replace')


def _attr(xml: str, name: str) -> str:
    m = re.search(rf'{re.escape(name)}\s*=\s*["\']([^"\']*)["\']', xml)
    return m.group(1) if m else ''


def login(sock: socket.socket, user: str, password: str) -> None:
    body = (
        f'<USER_AUTH_PARAM Username="{user}" Password="{password}" AuthMethod="1"/>'
    )
    sock.sendall(_frame('USER_AUTH_MESSAGE', 0, body))
    resp = _recv(sock)
    if not re.search(r'Sessionid\s*=\s*["\']([A-Za-z0-9_]+)["\']', resp):
        raise ValueError(f'login failed — response:\n{resp}')


# ── config dataclass ──────────────────────────────────────────────────────────
@dataclass
class LanConfig:
    ip:      str = ''
    netmask: str = ''
    gateway: str = ''
    dns1:    str = ''
    dns2:    str = ''
    mac:     str = ''
    mtu:     str = ''
    dhcp:    str = '0'

    @classmethod
    def from_xml(cls, xml: str) -> 'LanConfig':
        return cls(
            ip      = _attr(xml, 'IPAddress'),
            netmask = _attr(xml, 'Netmask'),
            gateway = _attr(xml, 'Gateway'),
            dns1    = _attr(xml, 'DNS1'),
            dns2    = _attr(xml, 'DNS2'),
            mac     = _attr(xml, 'MacAddress'),
            mtu     = _attr(xml, 'MTU'),
            dhcp    = _attr(xml, 'DHCP') or '0',
        )

    def to_set_xml(self) -> str:
        """Attribute order confirmed from firmware MakeNetworkLANCfgXml."""
        return (
            f'<LANConfig'
            f' MacAddress="{self.mac}"'
            f' DHCP="{self.dhcp}"'
            f' IPAddress="{self.ip}"'
            f' Netmask="{self.netmask}"'
            f' Gateway="{self.gateway}"'
            f' DNS1="{self.dns1}"'
            f' DNS2="{self.dns2}"'
            f'/>'
        )

    def pretty(self) -> str:
        return '\n'.join([
            f"  IP      : {self.ip}",
            f"  Netmask : {self.netmask}",
            f"  Gateway : {self.gateway}",
            f"  DNS1    : {self.dns1}",
            f"  DNS2    : {self.dns2}",
            f"  MAC     : {self.mac}",
            f"  MTU     : {self.mtu}",
            f"  DHCP    : {'enabled' if self.dhcp == '1' else 'disabled'}",
        ])


# ── camera operations ─────────────────────────────────────────────────────────
def get_lan_config(sock: socket.socket) -> LanConfig:
    sock.sendall(_frame('SYSTEM_CONFIG_GET_MESSAGE', 305, ''))
    resp = _recv(sock)
    if _attr(resp, 'Msg_flag') != '0':
        raise ValueError(f'GET failed: {resp.strip()[:120]}')
    return LanConfig.from_xml(resp)


def set_lan_config(sock: socket.socket, cfg: LanConfig) -> str:
    """CMD 325, no Sessionid in body — confirmed working."""
    sock.sendall(_frame('SYSTEM_CONFIG_SET_MESSAGE', 325, cfg.to_set_xml()))
    return _recv(sock)


def reboot_camera(sock: socket.socket) -> str:
    """SYSTEM_CONTROL_MESSAGE CMD 1007 — confirmed working."""
    try:
        sock.sendall(_frame('SYSTEM_CONTROL_MESSAGE', 1007, ''))
        resp = _recv(sock)
        return 'Reboot accepted' if _attr(resp, 'Msg_flag') == '0' else f'flag={_attr(resp, "Msg_flag")}'
    except ConnectionError:
        return 'Connection closed — camera rebooting'


# ── commands ──────────────────────────────────────────────────────────────────
def cmd_show(ip: str, args) -> None:
    print(f'\n  {ip}')
    print(f'  {"─" * 36}')
    try:
        with socket.create_connection((ip, args.port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            login(sock, args.user, args.password)
            print(get_lan_config(sock).pretty())
    except Exception as e:
        print(f'  ERROR: {e}')


def cmd_set(ip: str, args) -> None:
    print(f'\n  {ip}')
    print(f'  {"─" * 36}')
    try:
        with socket.create_connection((ip, args.port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            login(sock, args.user, args.password)

            current = get_lan_config(sock)
            print('  Current:')
            print(current.pretty())

            new = dc_replace(
                current,
                ip      = args.new_ip  or current.ip,
                netmask = args.netmask or current.netmask,
                gateway = args.gateway or current.gateway,
                dns1    = args.dns1    or current.dns1,
                dns2    = args.dns2    or current.dns2,
                mtu     = args.mtu     or current.mtu,
                dhcp    = {'on': '1', 'off': '0'}.get(args.dhcp, current.dhcp),
            )

            if new == current:
                print('\n  Nothing to change.')
                return

            print('\n  New:')
            print(new.pretty())

            if args.dry_run:
                print(f'\n  [dry-run] XML:\n  {new.to_set_xml()}')
                return

            resp = set_lan_config(sock, new)
            if _attr(resp, 'Msg_flag') != '0':
                print(f'  SET failed: {resp.strip()[:200]}')
                return

            print('  SET accepted.')
            print(f'  {reboot_camera(sock)}')
            print('  Wait ~30s then verify.')

            if args.new_ip and args.new_ip != current.ip:
                print(f'\n  IP changed: {current.ip} → {args.new_ip}')

    except ConnectionError as e:
        print(f'  Connection closed after SET (expected if IP changed): {e}')
        if args.new_ip:
            print(f'  Reconnect to {args.new_ip} to verify.')
    except Exception as e:
        print(f'  ERROR: {e}')


def cmd_reboot(ip: str, args) -> None:
    print(f'\n  Rebooting {ip}…')
    try:
        with socket.create_connection((ip, args.port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            login(sock, args.user, args.password)
            print(f'  {reboot_camera(sock)}')
    except ConnectionError:
        print('  Connection closed — camera is rebooting.')
    except Exception as e:
        print(f'  ERROR: {e}')


# ── target parsing ────────────────────────────────────────────────────────────
def parse_targets(args) -> list[str]:
    targets = []
    if args.host:
        targets.append(args.host)
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line.split()[0])
        except FileNotFoundError:
            print(f'File not found: {args.file}', file=sys.stderr)
            sys.exit(1)
    if not targets:
        print('Specify --host <ip> or --file <file>', file=sys.stderr)
        sys.exit(1)
    return targets


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * W)
    print("  Topsee / Tianshitong camera network config")
    print("  Authors: Claude (Anthropic), silvije2 (https://github.com/silvije2)")
    print("=" * W)
    ap = argparse.ArgumentParser(
        description='Topsee camera network configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('command', choices=['show', 'set', 'reboot'])

    tg = ap.add_argument_group('target')
    tg.add_argument('--host', metavar='IP',   help='camera IP address')
    tg.add_argument('--file', metavar='FILE', help='file with one IP per line')

    au = ap.add_argument_group('auth')
    au.add_argument('--user',     default=DEFAULT_USER)
    au.add_argument('--password', default=DEFAULT_PASSWORD)
    au.add_argument('--port',     default=DEFAULT_PORT,    type=int)
    au.add_argument('--timeout',  default=DEFAULT_TIMEOUT, type=int)

    nw = ap.add_argument_group('network params (set command)')
    nw.add_argument('--new-ip',  metavar='IP',   help='new IP address')
    nw.add_argument('--netmask', metavar='MASK', help='subnet mask')
    nw.add_argument('--gateway', metavar='IP',   help='default gateway')
    nw.add_argument('--dns1',    metavar='IP',   help='primary DNS')
    nw.add_argument('--dns2',    metavar='IP',   help='secondary DNS')
    nw.add_argument('--mtu',     metavar='N',    help='MTU')
    nw.add_argument('--dhcp',    choices=['on', 'off'])
    nw.add_argument('--dry-run', action='store_true',
                    help='show what would be sent without sending it')

    args = ap.parse_args()

    if args.command == 'set':
        if not any([args.new_ip, args.netmask, args.gateway,
                    args.dns1, args.dns2, args.mtu, args.dhcp]):
            ap.error('set requires at least one of: '
                     '--new-ip --netmask --gateway --dns1 --dns2 --mtu --dhcp')

    targets = parse_targets(args)
    dispatch = {'show': cmd_show, 'set': cmd_set, 'reboot': cmd_reboot}
    for ip in targets:
        dispatch[args.command](ip, args)
    print()


if __name__ == '__main__':
    main()

