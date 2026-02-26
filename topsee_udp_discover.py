#!/usr/bin/env python3
"""
Topsee / Tianshitong (天视通) IP Camera UDP Discovery Tool
==========================================================

Authors: Claude (Anthropic) — protocol reverse engineering from
    LinuxNetSDK_Release_x86_V22_20140529 binary analysis (disassembly of
    libNetSDK.so, frame structure, XML protocol, UDP response flow, ONVIF
    integration), full implementation

Contributors (silvije2) — live packet capture validation, tcpdump-based
    protocol debugging, ONVIF script reference, firewall diagnostics,
    feature direction

Protocol details (reverse-engineered from libNetSDK.so + live packet capture):

  UDP Discovery (port 3001):
    - Client binds UDP port 3001 (SO_BROADCAST + SO_REUSEADDR + SO_REUSEPORT)
    - Client broadcasts SYSTEM_SEARCHIPC_MESSAGE Msg_code=1 to 255.255.255.255:3001
    - Camera responds by broadcasting Msg_code=3 back to 255.255.255.255:3001
      (NOT back to sender source port — must bind to 3001 to receive responses)
    - Firewall must allow inbound UDP port 3001

  TCP Control (port 8091):
    - Frame: [58 91 58 51] magic + 4-byte LE length + GB2312 XML payload
    - Login: USER_AUTH_MESSAGE -> returns Sessionid
    - Query: SYSTEM_CONFIG_GET_MESSAGE CMD 600 -> MediaStreamConfig (ports, auth)

  ONVIF (port 80):
    - Standard SOAP/WS-Security (PasswordDigest) calls
    - GetDeviceInformation, GetNetworkInterfaces
    - GetProfiles -> GetStreamUri (main + sub stream)
    - GetSnapshotUri (main + sub snapshot)

  Other ports confirmed by nmap:
    - 80/tcp   : ONVIF (gSOAP 2.8)
    - 554/tcp : RTSP (Live555)
    - 8091/tcp : Proprietary SDK control channel
    - 3001/udp : UDP discovery

Firewall rules needed:
  iptables : sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT
  ufw      : sudo ufw allow 3001/udp

Usage:
  sudo python3 topsee_udp_discover.py
  sudo python3 topsee_udp_discover.py --iface 192.168.1.1
  sudo python3 topsee_udp_discover.py --timeout 10 --repeat 5
  sudo python3 topsee_udp_discover.py --no-tcp    # UDP discovery only
  sudo python3 topsee_udp_discover.py --verbose   # show raw XML
"""

import socket
import struct
import re
import time
import argparse
import hashlib
import base64
import os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Constants ─────────────────────────────────────────────────────────────────
UDP_PORT          = 3001
TCP_PORT          = 8091
ONVIF_PORT        = 80
BROADCAST         = '255.255.255.255'
ENCODING          = 'gb2312'
UDP_RECV_BUF      = 8192
MAGIC             = bytes.fromhex('58915851')

MSG_CODE_DISCOVER = 1
MSG_CODE_RESPONSE = 3

DEFAULT_CREDS = [
    ('admin', ''),
    ('admin', 'admin'),
    ('admin', '123456'),
]

USAGE = """
Usage:
  sudo python3 topsee_udp_discover.py
  sudo python3 topsee_udp_discover.py --iface 192.168.1.1
  sudo python3 topsee_udp_discover.py --broadcast 192.168.1.255
  sudo python3 topsee_udp_discover.py --timeout 10 --repeat 5
  sudo python3 topsee_udp_discover.py --no-tcp
  sudo python3 topsee_udp_discover.py --threads 20
  sudo python3 topsee_udp_discover.py --verbose

Firewall (run once before discovery):
  iptables:  sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT
  ufw:       sudo ufw allow 3001/udp
"""


# ── UDP packet ────────────────────────────────────────────────────────────────
def build_udp_packet() -> bytes:
    xml = (
        '<?xml version="1.0" encoding="GB2312" ?>\n'
        '<XML_TOPSEE>\n'
        '<MESSAGE_HEADER\n'
        'Msg_type="SYSTEM_SEARCHIPC_MESSAGE"\n'
        f'Msg_code="{MSG_CODE_DISCOVER}"\n'
        'Msg_flag="0"\n'
        '/>\n'
        '<MESSAGE_BODY>\n'
        '</MESSAGE_BODY>\n'
        '</XML_TOPSEE>'
    )
    return xml.encode(ENCODING)


# ── TCP framing ───────────────────────────────────────────────────────────────
def tcp_encode(xml: str) -> bytes:
    payload = xml.encode(ENCODING)
    return MAGIC + struct.pack('<I', len(payload)) + payload


def tcp_recv(sock: socket.socket) -> str | None:
    def recv_n(n):
        buf = b''
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf
    hdr = recv_n(8)
    if not hdr or hdr[:4] != MAGIC:
        return None
    length = struct.unpack('<I', hdr[4:])[0]
    if length == 0 or length > 2 * 1024 * 1024:
        return None
    payload = recv_n(length)
    if not payload:
        return None
    return payload.decode(ENCODING, errors='replace')


def tcp_msg_login(user: str, password: str) -> str:
    return (
        '<?xml version="1.0" encoding="GB2312" ?>'
        '<XML_TOPSEE>'
        '<MESSAGE_HEADER Msg_type="USER_AUTH_MESSAGE" '
        'Msg_code="CMD_USER_AUTH" Msg_flag="0"/>'
        '<MESSAGE_BODY>'
        f'<USER_AUTH_PARAM Username="{user}" Password="{password}" AuthMethod="1"/>'
        '<ENCRYPT Capbility="SUPPORT_TPE" Version="1"/>'
        '</MESSAGE_BODY>'
        '</XML_TOPSEE>'
    )


def tcp_msg_get_mediastream(session_id: str) -> str:
    return (
        '<?xml version="1.0" encoding="GB2312" ?>'
        '<XML_TOPSEE>'
        '<MESSAGE_HEADER Msg_type="SYSTEM_CONFIG_GET_MESSAGE" '
        'Msg_code="600" Msg_flag="1"/>'
        f'<MESSAGE_BODY Sessionid="{session_id}">'
        '</MESSAGE_BODY>'
        '</XML_TOPSEE>'
    )


# ── ONVIF SOAP ────────────────────────────────────────────────────────────────
def _wsse_header(user: str, password: str) -> str:
    nonce_raw = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_raw).decode()
    created   = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    digest    = base64.b64encode(
        hashlib.sha1(nonce_raw + created.encode() + password.encode()).digest()
    ).decode()
    return (
        '<soap:Header>'
        '<wsse:Security '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '<wsse:UsernameToken>'
        f'<wsse:Username>{user}</wsse:Username>'
        f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>'
        f'<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>'
        f'<wsu:Created>{created}</wsu:Created>'
        '</wsse:UsernameToken>'
        '</wsse:Security>'
        '</soap:Header>'
    )


def _soap(user: str, password: str, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope '
        'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
        'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
        'xmlns:tt="http://www.onvif.org/ver10/schema">'
        f'{_wsse_header(user, password)}'
        f'<soap:Body>{body}</soap:Body>'
        '</soap:Envelope>'
    )


def _http_post(ip: str, port: int, path: str, body: str,
               timeout: float = 5.0) -> str | None:
    payload = body.encode('utf-8')
    request = (
        f'POST {path} HTTP/1.1\r\n'
        f'Host: {ip}:{port}\r\n'
        f'Content-Type: application/soap+xml; charset=utf-8\r\n'
        f'Content-Length: {len(payload)}\r\n'
        f'Connection: close\r\n'
        f'\r\n'
    ).encode() + payload

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(request)
        resp = b''
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
            if len(resp) > 512 * 1024:
                break
        sock.close()
        # Strip HTTP headers
        if b'\r\n\r\n' in resp:
            resp = resp.split(b'\r\n\r\n', 1)[1]
        # Handle chunked transfer encoding
        if b'\r\n' in resp[:10]:
            try:
                lines = resp.split(b'\r\n')
                body_parts = []
                i = 0
                while i < len(lines):
                    try:
                        size = int(lines[i], 16)
                    except ValueError:
                        body_parts.append(lines[i])
                        i += 1
                        continue
                    if size == 0:
                        break
                    i += 1
                    if i < len(lines):
                        body_parts.append(lines[i])
                    i += 1
                resp = b'\r\n'.join(body_parts)
            except Exception:
                pass
        return resp.decode('utf-8', errors='replace')
    except OSError:
        return None


def _xml_val(xml: str, *tags: str) -> str:
    """Extract first matching tag value, trying each tag name."""
    for tag in tags:
        m = re.search(rf'<(?:\w+:)?{tag}[^>]*>(.*?)</(?:\w+:)?{tag}>', xml, re.DOTALL)
        if m:
            return m.group(1).strip()
    return ''


def _xml_all(xml: str, tag: str) -> list[str]:
    return [m.group(1).strip()
            for m in re.finditer(
                rf'<(?:\w+:)?{tag}[^>]*>(.*?)</(?:\w+:)?{tag}>', xml, re.DOTALL)]


def onvif_query(ip: str, user: str, password: str,
                port: int = ONVIF_PORT, timeout: float = 5.0) -> dict:
    """
    Query ONVIF device on port 80. Returns dict with device info,
    stream URIs, and snapshot URIs.
    """
    result: dict = {}

    # ── GetDeviceInformation ──────────────────────────────────────────────────
    resp = _http_post(ip, port, '/onvif/device_service',
                      _soap(user, password, '<tds:GetDeviceInformation/>'),
                      timeout)
    if resp:
        result['onvif_manufacturer'] = _xml_val(resp, 'Manufacturer')
        result['onvif_model']        = _xml_val(resp, 'Model')
        result['onvif_firmware']     = _xml_val(resp, 'FirmwareVersion')
        result['onvif_serial']       = _xml_val(resp, 'SerialNumber')
        result['onvif_hardware']     = _xml_val(resp, 'HardwareId')

    # ── GetNetworkInterfaces ──────────────────────────────────────────────────
    resp = _http_post(ip, port, '/onvif/device_service',
                      _soap(user, password, '<tds:GetNetworkInterfaces/>'),
                      timeout)
    if resp:
        result['onvif_mac'] = _xml_val(resp, 'HwAddress')
        result['onvif_ip']  = _xml_val(resp, 'Address')

    # ── GetProfiles ───────────────────────────────────────────────────────────
    resp = _http_post(ip, port, '/onvif/media_service',
                      _soap(user, password, '<trt:GetProfiles/>'),
                      timeout)
    if not resp:
        return result

    # Extract profile tokens (first = main, second = sub)
    tokens = re.findall(r'<(?:\w+:)?Profiles[^>]+token="([^"]+)"', resp)
    if not tokens:
        tokens = [m.group(1) for m in
                  re.finditer(r'token="([^"]+)"', resp)]
    tokens = list(dict.fromkeys(tokens))  # deduplicate, preserve order

    if not tokens:
        return result

    def get_stream_uri(token: str) -> str:
        body = (
            '<trt:GetStreamUri>'
            '<trt:StreamSetup>'
            '<tt:Stream>RTP-Unicast</tt:Stream>'
            '<tt:Transport><tt:Protocol>TCP</tt:Protocol></tt:Transport>'
            '</trt:StreamSetup>'
            f'<trt:ProfileToken>{token}</trt:ProfileToken>'
            '</trt:GetStreamUri>'
        )
        r = _http_post(ip, port, '/onvif/media_service',
                       _soap(user, password, body), timeout)
        return _xml_val(r or '', 'Uri') or ''

    def get_snapshot_uri(token: str) -> str:
        body = (
            '<trt:GetSnapshotUri>'
            f'<trt:ProfileToken>{token}</trt:ProfileToken>'
            '</trt:GetSnapshotUri>'
        )
        r = _http_post(ip, port, '/onvif/media_service',
                       _soap(user, password, body), timeout)
        return _xml_val(r or '', 'Uri') or ''

    if len(tokens) >= 1:
        result['onvif_stream_main']    = get_stream_uri(tokens[0])
        result['onvif_snapshot_main']  = get_snapshot_uri(tokens[0])
    if len(tokens) >= 2:
        result['onvif_stream_sub']     = get_stream_uri(tokens[1])
        result['onvif_snapshot_sub']   = get_snapshot_uri(tokens[1])

    result['onvif_ok'] = True
    return result


# ── TCP enrichment ────────────────────────────────────────────────────────────
def tcp_enrich(ip: str, port: int, credentials: list) -> dict:
    for user, password in credentials:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((ip, port))
            sock.settimeout(5.0)
        except OSError:
            return {}
        try:
            sock.sendall(tcp_encode(tcp_msg_login(user, password)))
            resp = tcp_recv(sock)
            if not resp:
                sock.close()
                continue
            m = re.search(r'Sessionid\s*=\s*["\']([a-zA-Z0-9_]+)["\']', resp)
            if not m:
                sock.close()
                continue
            session_id = m.group(1)
            sock.sendall(tcp_encode(tcp_msg_get_mediastream(session_id)))
            resp = tcp_recv(sock)
            sock.close()
            attrs = dict(re.findall(r'([\w]+)\s*=\s*"([^"]*)"', resp or ''))
            return {
                'tcp_user':     user,
                'tcp_pass':     password,
                'tcp_vidport':  attrs.get('VideoPort')     or attrs.get('videoPort', ''),
                'tcp_ptzport':  attrs.get('PTZPort')       or attrs.get('ptzPort', ''),
                'tcp_webport':  attrs.get('WEBPort')       or attrs.get('webPort', ''),
                'tcp_rtp_rtsp': attrs.get('RTPOverRTSP')   or attrs.get('rtpoverrtsp', ''),
                'tcp_auth':     attrs.get('Auth')          or attrs.get('auth', ''),
                'tcp_rtsp_n':   attrs.get('RTSPClientNumber', ''),
                'tcp_rtp_size': attrs.get('RTPPacketSize', ''),
            }
        except OSError:
            try: sock.close()
            except Exception: pass
            continue
    return {}


# ── UDP response parser ───────────────────────────────────────────────────────
def parse_udp_response(data: bytes, src_ip: str) -> dict | None:
    try:
        xml_str = data.decode(ENCODING, errors='replace').strip()
    except Exception:
        return None
    if '<XML_TOPSEE>' not in xml_str:
        return None
    m = re.search(r'Msg_code="(\d+)"', xml_str)
    if not m or m.group(1) != str(MSG_CODE_RESPONSE):
        return None

    def el(tag: str, attr: str) -> str:
        m = re.search(rf'<{tag}[\s\S]*?{attr}="([^"]*)"', xml_str, re.IGNORECASE)
        return m.group(1).strip() if m else ''

    def accounts() -> list[dict]:
        return [
            {
                'username': a.get('Username') or a.get('userName', ''),
                'password': a.get('Password') or a.get('password', ''),
                'status':   a.get('Status')   or a.get('status', ''),
            }
            for a in [
                dict(re.findall(r'(\w+)="([^"]*)"', blk.group(1)))
                for blk in re.finditer(r'<Account([\s\S]*?)/>', xml_str)
            ]
            if a.get('Username') or a.get('userName')
        ]

    return {
        'ip':            src_ip,
        'device_type':   el('DEVICE_TYPE', 'DeviceType'),
        'device_module': el('DEVICE_TYPE', 'DeviceModule'),
        'serial':        el('IPC_SERIALNUMBER', 'SerialNumber'),
        'dev_id':        el('IPC_SERIALNUMBER', 'DevID'),
        'fw_version':    el('VERSION', 'FileSystemVersion'),
        'osd_str':       el('OSD', 'OsdStr'),
        'mac':           el('LANConfig', 'MacAddress'),
        'dhcp':          el('LANConfig', 'DHCP'),
        'lan_ip':        el('LANConfig', 'IPAddress'),
        'netmask':       el('LANConfig', 'Netmask'),
        'gateway':       el('LANConfig', 'Gateway'),
        'dns1':          el('LANConfig', 'DNS1'),
        'dns2':          el('LANConfig', 'DNS2'),
        'mtu':           el('LANConfig', 'MTU'),
        'all_net':       el('LANConfig', 'AllNetConnectEnable'),
        'video_port':    el('StreamAccess', 'VideoPort'),
        'ptz_port':      el('StreamAccess', 'PTZPort'),
        'web_port':      el('StreamAccess', 'WEBPort'),
        'rtp_over_rtsp': el('StreamAccess', 'RTPOverRTSP'),
        'auth':          el('StreamAccess', 'Auth'),
        'rtsp_clients':  el('StreamAccess', 'RTSPClientNumber'),
        'rtp_pkt_size':  el('StreamAccess', 'RTPPacketSize'),
        'users':         accounts(),
        # filled later
        'tcp_user': '', 'tcp_pass': '', 'tcp_vidport': '', 'tcp_ptzport': '',
        'tcp_webport': '', 'tcp_rtp_rtsp': '', 'tcp_auth': '',
        'tcp_rtsp_n': '', 'tcp_rtp_size': '',
        'onvif_manufacturer': '', 'onvif_model': '', 'onvif_firmware': '',
        'onvif_serial': '', 'onvif_hardware': '', 'onvif_mac': '',
        'onvif_ip': '', 'onvif_stream_main': '', 'onvif_stream_sub': '',
        'onvif_snapshot_main': '', 'onvif_snapshot_sub': '',
        'onvif_ok': False,
        'raw': xml_str,
    }


# ── Print ─────────────────────────────────────────────────────────────────────
W = 68

def _row(label: str, value: str, w: int = 18) -> None:
    if value:
        print(f"  {label:<{w}}: {value}")


def print_camera(c: dict, verbose: bool = False) -> None:
    vid_port = c.get('tcp_vidport') or c.get('video_port', '')
    ptz_port = c.get('tcp_ptzport') or c.get('ptz_port', '')
    web_port = c.get('tcp_webport') or c.get('web_port', '')

    print(f"\n{'═'*W}")
    dtype = c.get('onvif_model') or c.get('device_type') or '(unknown)'
    print(f"  {c['ip']}  —  {dtype}")
    print(f"{'─'*W}")

    # Identity — prefer ONVIF data, fall back to UDP
    _row('Serial Number',   c.get('onvif_serial')   or c.get('serial', ''))
    _row('Hardware ID',     c.get('onvif_hardware')  or c.get('dev_id', ''))
    _row('Manufacturer',    c.get('onvif_manufacturer', ''))
    _row('Device Module',   c.get('device_module', ''))
    _row('Firmware',        c.get('onvif_firmware')  or c.get('fw_version', ''))
    if c.get('osd_str'):
        _row('OSD String',  c['osd_str'])

    # Network
    print(f"{'─'*W}")
    _row('MAC Address',     c.get('onvif_mac')       or c.get('mac', ''))
    _row('IP Address',      c.get('onvif_ip')        or c.get('lan_ip') or c['ip'])
    _row('Netmask',         c.get('netmask', ''))
    _row('Gateway',         c.get('gateway', ''))
    dns = '  /  '.join(filter(None, [c.get('dns1'), c.get('dns2')]))
    _row('DNS',             dns)
    _row('MTU',             c.get('mtu', ''))
    _row('DHCP',            'enabled' if c.get('dhcp') == '1' else 'disabled')

    # Ports
    print(f"{'─'*W}")
    _row('RTSP Port',       vid_port)
    _row('SDK/PTZ Port',    ptz_port)
    _row('Web/ONVIF Port',  web_port or str(ONVIF_PORT))
    rtr = c.get('tcp_rtp_rtsp') or c.get('rtp_over_rtsp', '')
    _row('RTPOverRTSP',     'yes' if rtr == '1' else 'no')
    _row('RTSP Auth',       'required' if (c.get('tcp_auth') or c.get('auth')) == '1' else 'none')
    _row('RTSP Clients',    c.get('tcp_rtsp_n') or c.get('rtsp_clients', ''))
    _row('RTP Packet Size', c.get('tcp_rtp_size') or c.get('rtp_pkt_size', ''))

    # Streams and snapshots from ONVIF
    if c.get('onvif_stream_main') or c.get('onvif_stream_sub'):
        print(f"{'─'*W}")
        _row('Main Stream',     c.get('onvif_stream_main', ''))
        _row('Sub Stream',      c.get('onvif_stream_sub', ''))
        _row('Main Snapshot',   c.get('onvif_snapshot_main', ''))
        _row('Sub Snapshot',    c.get('onvif_snapshot_sub', ''))

    # Credentials
    if c.get('tcp_user') or c.get('users'):
        print(f"{'─'*W}")
        if c.get('tcp_user'):
            print(f"  TCP/ONVIF Login  : {c['tcp_user']} / {c['tcp_pass']}")
        if c.get('users'):
            print(f"  Device Accounts  :")
            for u in c['users']:
                s = f"  [{u['status']}]" if u.get('status') else ''
                print(f"    {u['username']:<16} / {u['password']:<16}{s}")

    if verbose:
        print(f"{'─'*W}")
        print(f"  Raw UDP XML:\n{c['raw']}")


def ip_sort_key(c: dict) -> tuple:
    try:
        return tuple(int(x) for x in c['ip'].split('.'))
    except Exception:
        return (0, 0, 0, 0)


def print_summary(cameras: list[dict]) -> None:
    print(f"\n{'═'*W}")
    print(f"  SUMMARY — {len(cameras)} camera(s) found")
    print(f"{'─'*W}")
    print(f"  {'IP':<16}  {'Type':<20}  {'Auth':<18}  Main Stream")
    print(f"  {'─'*14}  {'─'*18}  {'─'*16}  {'─'*30}")
    for c in cameras:
        dtype = (c.get('onvif_model') or c.get('device_type') or '—')[:18]
        auth  = f"{c['tcp_user']}/{c['tcp_pass']}" if c.get('tcp_user') else '—'
        stream = c.get('onvif_stream_main') or '—'
        print(f"  {c['ip']:<16}  {dtype:<20}  {auth:<18}  {stream}")
    print(f"{'═'*W}\n")


# ── UDP socket ────────────────────────────────────────────────────────────────
def make_udp_socket(iface: str = '') -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((iface if iface else '', UDP_PORT))
    return sock


def get_local_ips() -> set:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    return ips


# ── Main discovery ────────────────────────────────────────────────────────────
def discover(
    timeout: float = 8.0,
    iface: str = '',
    broadcast: str = BROADCAST,
    repeat: int = 5,
    do_tcp: bool = True,
    threads: int = 10,
    verbose: bool = False,
) -> list[dict]:

    local_ips = get_local_ips()
    print(f"[*] Local IPs   : {', '.join(sorted(local_ips))}")

    try:
        sock = make_udp_socket(iface)
    except PermissionError:
        print(f"[!] Permission denied — run with sudo")
        print(f"    Firewall: sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT")
        return []
    except OSError as e:
        print(f"[!] Socket error: {e}")
        return []

    bound = sock.getsockname()
    print(f"[*] Bound to    : {bound[0] or '0.0.0.0'}:{bound[1]}")
    print(f"[*] Broadcast   : {broadcast}:{UDP_PORT}")
    print(f"[*] Timeout     : {timeout}s  |  Repeat: {repeat}x")
    if do_tcp:
        print(f"[*] Enrichment  : TCP:{TCP_PORT} + ONVIF:{ONVIF_PORT}  ({threads} threads)")
    print()

    packet  = build_udp_packet()
    seen: dict[str, dict] = {}

    try:
        sock.sendto(packet, (broadcast, UDP_PORT))
        print(f"[*] Sent discovery packet 1/{repeat}")
    except OSError as e:
        print(f"[!] sendto failed: {e}")
        sock.close()
        return []

    sock.settimeout(0.3)
    deadline  = time.time() + timeout
    next_send = time.time() + (timeout / repeat)
    sends     = 1

    print(f"[*] Listening...\n")

    while time.time() < deadline:
        if sends < repeat and time.time() >= next_send:
            try:
                sock.sendto(packet, (broadcast, UDP_PORT))
                sends += 1
                print(f"[*] Sent discovery packet {sends}/{repeat}")
            except OSError:
                pass
            next_send = time.time() + (timeout / repeat)

        try:
            data, addr = sock.recvfrom(UDP_RECV_BUF)
        except socket.timeout:
            continue
        except OSError:
            break

        src_ip = addr[0]
        if src_ip in local_ips or src_ip in ('0.0.0.0', '127.0.0.1'):
            continue
        if src_ip in seen:
            continue

        info = parse_udp_response(data, src_ip)
        if info is None:
            if verbose:
                print(f"  [?] Unrecognised {len(data)}b from {src_ip}")
            continue

        seen[src_ip] = info
        print(f"[+] Found: {src_ip}  {info.get('device_type','?')}  SN:{info.get('serial','?')}")

    sock.close()

    if not seen or not do_tcp:
        return sorted(seen.values(), key=ip_sort_key)

    # ── Enrichment ────────────────────────────────────────────────────────────
    print(f"\n[*] Enriching {len(seen)} camera(s) via TCP + ONVIF...\n")

    def enrich(ip: str, cam: dict) -> tuple[str, dict]:
        # Build credential list: discovered accounts first, then defaults
        creds, seen_c = [], set()
        for u in cam.get('users', []):
            if u.get('username'):
                c = (u['username'], u.get('password', ''))
                if c not in seen_c:
                    creds.append(c)
                    seen_c.add(c)
        for c in DEFAULT_CREDS:
            if c not in seen_c:
                creds.append(c)
                seen_c.add(c)

        tcp_data  = tcp_enrich(ip, TCP_PORT, creds)
        onvif_data: dict = {}

        # Use working credentials for ONVIF
        onvif_user = tcp_data.get('tcp_user', '')
        onvif_pass = tcp_data.get('tcp_pass', '')
        if onvif_user:
            onvif_data = onvif_query(ip, onvif_user, onvif_pass)
        else:
            # Try credentials without TCP login
            for u, p in creds:
                d = onvif_query(ip, u, p)
                if d.get('onvif_ok'):
                    onvif_data = d
                    # Store working creds
                    tcp_data['tcp_user'] = u
                    tcp_data['tcp_pass'] = p
                    break

        status = (
            f"TCP:{'ok' if tcp_data.get('tcp_user') else 'fail'}  "
            f"ONVIF:{'ok' if onvif_data.get('onvif_ok') else 'fail'}  "
            f"Streams:{1 if onvif_data.get('onvif_stream_main') else 0}+{1 if onvif_data.get('onvif_stream_sub') else 0}"
        )
        print(f"  [{ip}] {status}")

        result = {}
        result.update(tcp_data)
        result.update(onvif_data)
        return ip, result

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(enrich, ip, cam): ip for ip, cam in seen.items()}
        for future in as_completed(futures):
            ip, extra = future.result()
            seen[ip].update(extra)

    return sorted(seen.values(), key=ip_sort_key)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    print("=" * W)
    print("  Topsee / Tianshitong UDP Camera Discovery")
    print("  Authors: Claude (Anthropic), silvije2 (https://github.com/silvije2)")
    print("=" * W)
    print(USAGE)

    parser = argparse.ArgumentParser(
        description='Topsee/Tianshitong UDP camera discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--timeout',   type=float, default=8.0,
                        help='UDP listen duration in seconds (default: 8)')
    parser.add_argument('--repeat',    type=int,   default=5,
                        help='Discovery packets to send (default: 5)')
    parser.add_argument('--iface',     type=str,   default='',
                        help='Bind to specific interface IP (e.g. 192.168.1.1)')
    parser.add_argument('--broadcast', type=str,   default=BROADCAST,
                        help=f'Broadcast address (default: {BROADCAST})')
    parser.add_argument('--no-tcp',    action='store_true',
                        help='Skip TCP + ONVIF enrichment (UDP only)')
    parser.add_argument('--threads',   type=int,   default=10,
                        help='Parallel enrichment threads (default: 10)')
    parser.add_argument('--verbose',   action='store_true',
                        help='Print raw XML for each camera')
    args = parser.parse_args()

    cameras = discover(
        timeout   = args.timeout,
        iface     = args.iface,
        broadcast = args.broadcast,
        repeat    = args.repeat,
        do_tcp    = not args.no_tcp,
        threads   = args.threads,
        verbose   = args.verbose,
    )

    if not cameras:
        print("\n[!] No cameras found.")
        print("    - Run: sudo iptables -I INPUT -p udp --dport 3001 -j ACCEPT")
        print("    - Or:  sudo ufw allow 3001/udp")
        print("    - Try: --iface <your-interface-ip>")
        print("    - Try: --timeout 15 --repeat 8")
        return

    for c in cameras:
        print_camera(c, verbose=args.verbose)

    print_summary(cameras)


if __name__ == '__main__':
    main()
