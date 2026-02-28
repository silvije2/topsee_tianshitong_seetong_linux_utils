#!/usr/bin/env python3
"""
Topsee / Tianshitong (天视通) Camera Encoder Profile Tool
=========================================================
Authors: Claude (Anthropic) — protocol reverse engineering from
    LinuxNetSDK_Release_x86_V22_20140529 binary analysis (disassembly of
    libNetSDK.so, frame structure, XML protocol, UDP response flow, ONVIF
    integration), full implementation

Contributors (silvije2) — live packet capture validation, tcpdump-based
    protocol debugging, ONVIF script reference, firewall diagnostics,
    feature direction

Sets the video encoding profile (H264 / H265 / H265+) on one or more cameras
via the proprietary TCP SDK protocol on port 8091.

Background
----------
These cameras support H264, H265 and H265+ ("smart encoding") profiles.
H265+ gives the best compression but after a reboot the camera firmware
falls back to H265 for compatibility. A connected Topsee DVR can push it
back to H265+, but if you don't have the DVR (or just want to automate it)
this script does the same job directly.

Protocol
--------
1. TCP login on port 8091  (USER_AUTH_MESSAGE → Sessionid)
2. GET current video config  CMD 501 (CMD_GET_MEDIA_VIDEO_CONFIG)
   Camera returns a block containing:
     <EncodeConfig Stream="1" ... EncodeFormat="H265" .../>   ← main stream
     <EncodeConfig Stream="2" ... EncodeFormat="H265" .../>   ← sub stream
     <AdvanceEncodeConfig ... H265plus="1" H265subplus="1" DefaultH265plus="0" .../>
3. Patch EncodeFormat and H265plus/H265subplus flags as needed
4. SET video encode config  CMD 523 (CMD_SET_MEDIA_VIDEO_ENCODE)
                  body = patched <Encode>...</Encode> sub-block

Encoder values and what gets changed
-------------------------------------
  H264   → EncodeFormat="H264",  H265plus="0", H265subplus="0"
  H265   → EncodeFormat="H265",  H265plus="0", H265subplus="0"
  H265+  → EncodeFormat="H265",  H265plus="1", H265subplus="1"
           (H265+ is not a separate codec — it's H265 with the plus flag set)

Usage
-----
  # Set all discovered cameras to H265+
  sudo python3 topsee_set_encoder.py --discover --encoder H265+

  # Set a single camera
  python3 topsee_set_encoder.py --host 192.168.1.2 -u admin -p 123456 --encoder H265+

  # Set subnet range
  python3 topsee_set_encoder.py --host 192.168.1.0/24 --encoder H265+

  # Dry-run: show current profile, do not change anything
  python3 topsee_set_encoder.py --host 192.168.1.2 --dry-run

  # Set only the main stream; leave sub stream alone
  python3 topsee_set_encoder.py --host 192.168.1.2 --encoder H265+ --stream main

  # Read targets from file (one IP per line)
  python3 topsee_set_encoder.py --file cameras.txt --encoder H265+

  # Set bitrate for main and/or sub stream (kbps)
  python3 topsee_set_encoder.py --host 192.168.1.2 --main-bitrate 4000
  python3 topsee_set_encoder.py --host 192.168.1.2 --sub-bitrate 512
  python3 topsee_set_encoder.py --host 192.168.1.2 --main-bitrate 4000 --sub-bitrate 512

  # Combine encoder and bitrate in one call
  python3 topsee_set_encoder.py --host 192.168.1.2 --encoder H265+ \\
      --main-bitrate 4000 --sub-bitrate 512
"""

import socket
import struct
import re
import sys
import time
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Constants ─────────────────────────────────────────────────────────────────
TCP_PORT  = 8091
UDP_PORT  = 3001
ENCODING  = 'gb2312'
MAGIC     = bytes.fromhex('58915851')
BROADCAST = '255.255.255.255'

CMD_GET_MEDIA_VIDEO_CONFIG  = '501'   # CMD_MEDIA_CONFIG_BASE + 1
CMD_SET_MEDIA_VIDEO_ENCODE  = '523'   # CMD_MEDIA_CONFIG_BASE + 23  (Encode sub-block only)

DEFAULT_CREDS = [
    ('admin', ''),
    ('admin', 'admin'),
    ('admin', '123456'),
]


# ── TCP framing ───────────────────────────────────────────────────────────────
def tcp_encode(xml: str) -> bytes:
    payload = xml.encode(ENCODING)
    return MAGIC + struct.pack('<I', len(payload)) + payload


def tcp_recv(sock: socket.socket, timeout: float = 5.0) -> str | None:
    sock.settimeout(timeout)

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
    if length == 0 or length > 4 * 1024 * 1024:
        return None
    payload = recv_n(length)
    if not payload:
        return None
    return payload.decode(ENCODING, errors='replace')


# ── Camera session ────────────────────────────────────────────────────────────
class CameraSession:
    def __init__(self, ip: str, timeout: float = 5.0, verbose: bool = False):
        self.ip         = ip
        self.timeout    = timeout
        self.verbose    = verbose
        self.sock       = None
        self.session_id = ''
        self.user       = ''
        self.password   = ''

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, TCP_PORT))
            self.sock = s
            return True
        except OSError as e:
            if self.verbose:
                print(f"  [{self.ip}] connect: {e}")
            return False

    def login(self, credentials: list[tuple[str, str]]) -> bool:
        for user, password in credentials:
            xml = (
                '<?xml version="1.0" encoding="GB2312" ?>'
                '<XML_TOPSEE>'
                '<MESSAGE_HEADER Msg_type="USER_AUTH_MESSAGE" '
                'Msg_code="CMD_USER_AUTH" Msg_flag="0"/>'
                '<MESSAGE_BODY>'
                f'<USER_AUTH_PARAM Username="{user}" Password="{password}" AuthMethod="1"/>'
                '</MESSAGE_BODY>'
                '</XML_TOPSEE>'
            )
            try:
                self.sock.sendall(tcp_encode(xml))
                resp = tcp_recv(self.sock, self.timeout)
                if not resp:
                    continue
                m = re.search(r'Sessionid\s*=\s*["\']([a-zA-Z0-9_]+)["\']', resp)
                if m:
                    self.session_id = m.group(1)
                    self.user       = user
                    self.password   = password
                    if self.verbose:
                        print(f"  [{self.ip}] login OK as {user}")
                    return True
            except OSError:
                pass
        return False

    def send_cmd(self, msg_type: str, msg_code: str, body: str = '') -> str | None:
        """
        Build and send one XML_TOPSEE frame.

        """
        if body:
            body_xml = f'<MESSAGE_BODY>\n{body}\n</MESSAGE_BODY>'
        else:
            body_xml = '<MESSAGE_BODY/>'
        xml = (
            '<?xml version="1.0" encoding="GB2312" ?>\n'
            '<XML_TOPSEE>\n'
            '<MESSAGE_HEADER\n'
            f'Msg_type="{msg_type}"\n'
            f'Msg_code="{msg_code}"\n'
            'Msg_flag="0"\n'
            '/>\n'
            f'{body_xml}\n'
            '</XML_TOPSEE>'
        )
        try:
            self.sock.sendall(tcp_encode(xml))
            return tcp_recv(self.sock, self.timeout)
        except OSError:
            return None

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


# ── Video config parser ───────────────────────────────────────────────────────
def parse_encode_state(xml: str) -> dict:
    """
    Parse the GET response (CMD 501).  Returns:
      {
        'main_format':    'H265',           # EncodeFormat from Stream="1"
        'sub_format':     'H265',           # EncodeFormat from Stream="2"
        'main_plus':      '1',              # H265plus from AdvanceEncodeConfig
        'sub_plus':       '1',              # H265subplus
        'has_adv_config': True,             # AdvanceEncodeConfig element present
        'has_h265plus':   True,             # H265plus field present -> H265+ capable
        'h265_capable':   True,             # any H265 support detected
        'encode_block':   '<Encode>...</Encode>'  # sub-block to patch and send to CMD 523
      }

    CMD 523 (SET_MEDIA_VIDEO_ENCODE) expects only the <Encode>...</Encode> sub-block,
    NOT the full <Video> block that CMD 501 returns.  Sending the full block is accepted
    without an ErrorCode but silently ignored by the camera.
    """
    result = {
        'main_format':    '?',
        'sub_format':     '?',
        'main_plus':      '0',
        'sub_plus':       '0',
        'main_bitrate':   '',
        'sub_bitrate':    '',
        'main_framerate': '',
        'sub_framerate':  '',
        'has_adv_config': False,
        'has_h265plus':   False,
        'h265_capable':   False,
        'encode_block':   '',
    }

    # Extract the <Encode>...</Encode> sub-block — this is what CMD 523 expects
    m = re.search(r'(<Encode>[\s\S]*?</Encode>)', xml)
    if m:
        result['encode_block'] = m.group(1).strip()

    # <EncodeConfig Stream="1" ... EncodeFormat="H265" .../>
    for m in re.finditer(r'<EncodeConfig\s([^>]+?)/>', xml, re.DOTALL):
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        stream = attrs.get('Stream', '')
        fmt    = attrs.get('EncodeFormat', '?')
        if stream == '1':
            result['main_format']    = fmt
            result['main_bitrate']   = attrs.get('BitRate',   '')
            result['main_framerate'] = attrs.get('FrameRate', '')
        elif stream == '2':
            result['sub_format']     = fmt
            result['sub_bitrate']    = attrs.get('BitRate',   '')
            result['sub_framerate']  = attrs.get('FrameRate', '')
        if fmt in ('H265', 'H265+'):
            result['h265_capable'] = True

    # <AdvanceEncodeConfig ... H265plus="1" H265subplus="1" .../>
    m = re.search(r'<AdvanceEncodeConfig\s([^>]+?)/>', xml, re.DOTALL)
    if m:
        result['has_adv_config'] = True
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        result['main_plus'] = attrs.get('H265plus',    '0')
        result['sub_plus']  = attrs.get('H265subplus', '0')
        if 'H265plus' in attrs:
            result['has_h265plus'] = True
            result['h265_capable'] = True

    return result


def describe_encoder(fmt: str, plus: str) -> str:
    """Human-readable current encoder state: 'H265+', 'H265', 'H264', etc."""
    if fmt == 'H265' and plus == '1':
        return 'H265+'
    return fmt


# ── Config patcher ────────────────────────────────────────────────────────────
def patch_config(encode_block: str, target: str, stream: str = 'both',
                 main_bitrate:   int | None = None,
                 sub_bitrate:    int | None = None,
                 main_framerate: int | None = None,
                 sub_framerate:  int | None = None) -> str:
    """
    Patch the <Encode>...</Encode> sub-block in-place.
    Sent to CMD 523 (SET_MEDIA_VIDEO_ENCODE).

    target: 'H264' | 'H265' | 'H265+' | '' (empty = don't change encoder)
    stream: 'main' | 'sub' | 'both'
    main_bitrate / sub_bitrate: kbps integer or None (leave unchanged)

    Note: DefaultH265plus / DefaultH265subplus appear in the GET response but
    cannot be set via any TCP SDK command on this firmware — CMD 523 silently
    ignores them and CMD 521 closes the connection. They are left untouched.
    """
    if target == 'H265+':
        encode_fmt = 'H265'
        main_plus  = '1'
        sub_plus   = '1'
    elif target == 'H265':
        encode_fmt = 'H265'
        main_plus  = '0'
        sub_plus   = '0'
    elif target == 'H264':
        encode_fmt = 'H264'
        main_plus  = '0'
        sub_plus   = '0'
    else:
        encode_fmt = None  # don't touch EncodeFormat
        main_plus  = None
        sub_plus   = None

    patched = encode_block

    # ── Patch EncodeConfig elements (EncodeFormat + BitRate) ─────────────────
    def patch_encode_config(m):
        full  = m.group(0)
        inner = m.group(1)
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', inner))
        s     = attrs.get('Stream', '')

        do_encoder = encode_fmt is not None and (
            (stream == 'both') or
            (stream == 'main' and s == '1') or
            (stream == 'sub'  and s == '2')
        )
        bitrate_val = (
            main_bitrate if s == '1' else
            sub_bitrate  if s == '2' else
            None
        )
        framerate_val = (
            main_framerate if s == '1' else
            sub_framerate  if s == '2' else
            None
        )

        if not do_encoder and bitrate_val is None and framerate_val is None:
            return full

        if do_encoder:
            if 'EncodeFormat=' in inner:
                inner = re.sub(r'EncodeFormat="[^"]*"',
                               f'EncodeFormat="{encode_fmt}"', inner)
            else:
                inner = inner.rstrip() + f' EncodeFormat="{encode_fmt}"'

        if bitrate_val is not None:
            if 'BitRate=' in inner:
                inner = re.sub(r'BitRate="[^"]*"',
                               f'BitRate="{bitrate_val}"', inner)
            else:
                inner = inner.rstrip() + f' BitRate="{bitrate_val}"'

        if framerate_val is not None:
            if 'FrameRate=' in inner:
                inner = re.sub(r'FrameRate="[^"]*"',
                               f'FrameRate="{framerate_val}"', inner)
            else:
                inner = inner.rstrip() + f' FrameRate="{framerate_val}"'

        return f'<EncodeConfig {inner}/>'

    patched = re.sub(r'<EncodeConfig\s([^>]+?)/>', patch_encode_config,
                     patched, flags=re.DOTALL)

    # ── Patch AdvanceEncodeConfig ─────────────────────────────────────────────
    def patch_advance(m):
        full  = m.group(0)
        inner = m.group(1)

        def set_attr(block, name, value):
            # Negative lookbehind: 'H265plus' must not be preceded by a letter
            # (prevents matching DefaultH265plus when setting H265plus)
            pattern = rf'(?<![a-zA-Z]){re.escape(name)}="[^"]*"'
            if re.search(pattern, block):
                return re.sub(pattern, f'{name}="{value}"', block)
            return block  # field absent — leave as-is

        if main_plus is not None and stream in ('main', 'both'):
            inner = set_attr(inner, 'H265plus',    main_plus)
        if sub_plus is not None and stream in ('sub', 'both'):
            inner = set_attr(inner, 'H265subplus', sub_plus)

        return f'<AdvanceEncodeConfig {inner}/>'

    patched = re.sub(r'<AdvanceEncodeConfig\s([^>]+?)/>', patch_advance,
                     patched, flags=re.DOTALL)

    return patched


# ── Capability check ─────────────────────────────────────────────────────────
def check_capability(target: str, state: dict) -> str | None:
    """
    Return an error string if the camera likely doesn't support the requested
    encoder, or None if it looks safe to proceed.

    What we can infer from the GET response:
      - No AdvanceEncodeConfig at all  → older firmware, H264 only
      - AdvanceEncodeConfig present but no H265plus field
                                       → H265 capable but NOT H265+
      - AdvanceEncodeConfig with H265plus field
                                       → full H265+ support

    Note: absence of H265 capability doesn't mean the SET will brick the
    camera — it will almost certainly return an ErrorCode — but we refuse
    early to give a clear message rather than a cryptic error code.
    """
    if target in ('H265', 'H265+'):
        if not state['h265_capable']:
            return (
                'camera does not appear to support H265 '
                '(no AdvanceEncodeConfig / H265 indicators in GET response). '
                'Use --force to attempt anyway.'
            )
    if target == 'H265+':
        if not state['has_h265plus']:
            return (
                'camera does not appear to support H265+ '
                '(H265plus field absent from AdvanceEncodeConfig). '
                'Use --force to attempt anyway.'
            )
    return None


# ── Per-camera operation ──────────────────────────────────────────────────────
def process_camera(ip: str, credentials: list, target: str,
                   stream: str = 'both', dry_run: bool = False,
                   force: bool = False, verbose: bool = False,
                   timeout: float = 5.0,
                   main_bitrate:   int | None = None,
                   sub_bitrate:    int | None = None,
                   main_framerate: int | None = None,
                   sub_framerate:  int | None = None) -> dict:

    result = {
        'ip':            ip,
        'ok':            False,
        'login':         False,
        'prev_main':     '',
        'prev_sub':      '',
        'new_main':      '',
        'new_sub':       '',
        'prev_main_br':  '',
        'prev_sub_br':   '',
        'prev_main_fr':  '',
        'prev_sub_fr':   '',
        'skipped':       False,
        'error':         '',
        'warning':       '',
    }

    cam = CameraSession(ip, timeout, verbose)

    if not cam.connect():
        result['error'] = 'connect failed'
        return result

    if not cam.login(credentials):
        cam.close()
        result['error'] = 'auth failed'
        return result

    result['login'] = True

    # ── GET current config ────────────────────────────────────────────────────
    resp = cam.send_cmd('SYSTEM_CONFIG_GET_MESSAGE', CMD_GET_MEDIA_VIDEO_CONFIG)
    if not resp:
        cam.close()
        result['error'] = 'no GET response'
        return result

    if verbose:
        print(f"\n  [{ip}] GET response:\n{resp}\n")

    state = parse_encode_state(resp)
    result['prev_main']    = describe_encoder(state['main_format'], state['main_plus'])
    result['prev_sub']     = describe_encoder(state['sub_format'],  state['sub_plus'])
    result['prev_main_br'] = state['main_bitrate']
    result['prev_sub_br']  = state['sub_bitrate']
    result['prev_main_fr'] = state['main_framerate']
    result['prev_sub_fr']  = state['sub_framerate']

    if not state['encode_block']:
        cam.close()
        result['error'] = 'could not extract <Encode> block from GET response'
        return result

    # ── Capability check ──────────────────────────────────────────────────────
    if target:
        cap_err = check_capability(target, state)
        if cap_err and not force:
            cam.close()
            result['error'] = cap_err
            return result
        elif cap_err and force:
            result['warning'] = 'forced past capability check — ' + cap_err

    # ── Check if already set ──────────────────────────────────────────────────
    already = True
    if target:
        if stream in ('main', 'both') and result['prev_main'] != target:
            already = False
        if stream in ('sub',  'both') and result['prev_sub']  != target:
            already = False
    if main_bitrate is not None and str(main_bitrate) != state['main_bitrate']:
        already = False
    if sub_bitrate is not None and str(sub_bitrate) != state['sub_bitrate']:
        already = False
    if main_framerate is not None and str(main_framerate) != state['main_framerate']:
        already = False
    if sub_framerate is not None and str(sub_framerate) != state['sub_framerate']:
        already = False

    if already:
        result['skipped'] = True
        result['ok']      = True
        cam.close()
        return result

    # Fill in what the new state will be
    result['new_main'] = (target if target and stream in ('main','both') else result['prev_main'])
    result['new_sub']  = (target if target and stream in ('sub', 'both') else result['prev_sub'])

    if dry_run:
        result['ok'] = True
        cam.close()
        return result

    # ── Patch + SET via CMD 523 (encode params: codec, bitrate, H265plus flags) ─
    needs_523 = target or main_bitrate is not None or sub_bitrate is not None \
                or main_framerate is not None or sub_framerate is not None

    if needs_523:
        patched = patch_config(state['encode_block'], target, stream,
                               main_bitrate=main_bitrate,
                               sub_bitrate=sub_bitrate,
                               main_framerate=main_framerate,
                               sub_framerate=sub_framerate)

        if verbose:
            print(f"  [{ip}] Patched Encode block (CMD 523):\n{patched}\n")

        resp2 = cam.send_cmd('SYSTEM_CONFIG_SET_MESSAGE', CMD_SET_MEDIA_VIDEO_ENCODE, patched)

        if not resp2:
            cam.close()
            result['error'] = 'no SET response (CMD 523)'
            return result

        if verbose:
            print(f"  [{ip}] SET response (CMD 523):\n{resp2}\n")

        err_m = re.search(r'ErrorCode\s*=\s*"(\d+)"', resp2)
        if err_m and err_m.group(1) != '0':
            cam.close()
            result['error'] = f'camera rejected CMD 523 (ErrorCode={err_m.group(1)})'
            return result

    cam.close()
    result['ok'] = True
    return result


# ── UDP discovery ─────────────────────────────────────────────────────────────
def udp_discover(timeout: float = 8.0, verbose: bool = False) -> list[dict]:
    print("[*] Running UDP discovery (requires sudo for port 3001)...")
    pkt = (
        '<?xml version="1.0" encoding="GB2312" ?>\n'
        '<XML_TOPSEE>\n'
        '<MESSAGE_HEADER Msg_type="SYSTEM_SEARCHIPC_MESSAGE" Msg_code="1" Msg_flag="0"/>\n'
        '<MESSAGE_BODY>\n</MESSAGE_BODY>\n</XML_TOPSEE>'
    ).encode(ENCODING)

    local_ips: set[str] = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ips.add(s.getsockname()[0])
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', UDP_PORT))
    except PermissionError:
        print("[!] Cannot bind UDP port 3001 — run with sudo")
        return []

    found = {}
    deadline  = time.time() + timeout
    next_send = time.time()
    sends     = 0
    sock.settimeout(0.3)

    while time.time() < deadline:
        if time.time() >= next_send and sends < 5:
            try:
                sock.sendto(pkt, (BROADCAST, UDP_PORT))
                sends += 1
            except OSError: pass
            next_send = time.time() + 1.5

        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout: continue
        except OSError: break

        src_ip = addr[0]
        if src_ip in local_ips or src_ip in found: continue

        try:
            xml_str = data.decode(ENCODING, errors='replace')
        except Exception: continue

        if '<XML_TOPSEE>' not in xml_str: continue
        m = re.search(r'Msg_code="(\d+)"', xml_str)
        if not m or m.group(1) != '3': continue

        creds = []
        for acc in re.finditer(r'<Account([\s\S]*?)/>', xml_str):
            a = dict(re.findall(r'(\w+)="([^"]*)"', acc.group(1)))
            u = a.get('Username') or a.get('userName', '')
            p = a.get('Password') or a.get('password', '')
            if u:
                creds.append((u, p))

        found[src_ip] = {'ip': src_ip, 'creds': creds}
        print(f"[+] Discovered: {src_ip}")

    sock.close()
    return list(found.values())


# ── IP range expansion ────────────────────────────────────────────────────────
def expand_hosts(spec: str) -> list[str]:
    if '/' in spec:
        try:
            return [str(h) for h in ipaddress.ip_network(spec, strict=False).hosts()]
        except ValueError:
            print(f"[!] Invalid CIDR: {spec}")
            return []
    if '-' in spec.split('.')[-1]:
        prefix, rng = spec.rsplit('.', 1)
        lo, hi = rng.split('-')
        return [f"{prefix}.{i}" for i in range(int(lo), int(hi)+1)]
    return [spec]


# ── Output ────────────────────────────────────────────────────────────────────
W = 66



# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    print("=" * W)
    print("  Topsee / Tianshitong Camera Encoder Profile Tool")
    print("  Authors: Claude (Anthropic), silvije2 (https://github.com/silvije2)")
    print("=" * W)

    # Print usage section from docstring
    doc_lines = __doc__.split('\n')
    in_usage  = False
    for line in doc_lines:
        if line.strip().startswith('Usage'):
            in_usage = True
        if in_usage:
            print(line)

    print()

    parser = argparse.ArgumentParser(
        description='Set H264/H265/H265+ encoding on Topsee/Tianshitong cameras',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument('--host',     help='IP, CIDR (192.168.1.0/24), or range (192.168.1.1-20)')
    src.add_argument('--file',     help='File with one IP per line')
    src.add_argument('--discover', action='store_true', help='UDP broadcast discovery')

    parser.add_argument('--encoder',  choices=['H264', 'H265', 'H265+'],
                        help='Target encoder profile')
    parser.add_argument('--stream',   choices=['main', 'sub', 'both'], default='both',
                        help='Which stream to change encoder/bitrate on (default: both)')
    parser.add_argument('--main-bitrate',   type=int, metavar='KBPS',
                        help='Set main stream BitRate (kbps), e.g. 4000')
    parser.add_argument('--sub-bitrate',    type=int, metavar='KBPS',
                        help='Set sub stream BitRate (kbps), e.g. 512')
    parser.add_argument('--main-framerate', type=int, metavar='FPS',
                        help='Set main stream FrameRate (fps), e.g. 25')
    parser.add_argument('--sub-framerate',  type=int, metavar='FPS',
                        help='Set sub stream FrameRate (fps), e.g. 15')
    parser.add_argument('-u', '--user',     default='', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('--dry-run',  action='store_true',
                        help='Show current encoder state without making changes')
    parser.add_argument('--force',    action='store_true',
                        help='Skip capability check and attempt SET even on unsupported cameras')
    parser.add_argument('--threads',  type=int,   default=10)
    parser.add_argument('--timeout',  type=float, default=5.0)
    parser.add_argument('--verbose',  action='store_true', help='Show raw XML')
    args = parser.parse_args()

    has_any_change = (
        args.encoder or
        args.main_bitrate    is not None or
        args.sub_bitrate     is not None or
        args.main_framerate  is not None or
        args.sub_framerate   is not None
    )
    if not has_any_change and not args.dry_run:
        parser.error(
            'specify at least one change: --encoder, --main-bitrate, --sub-bitrate, '
            '--main-framerate, --sub-framerate  (or use --dry-run to read state)'
        )

    # ── Build target list ─────────────────────────────────────────────────────
    targets: list[dict] = []

    if args.discover:
        discovered = sorted(udp_discover(verbose=args.verbose),
                            key=lambda d: ipaddress.ip_address(d['ip']))
        for d in discovered:
            creds = d.get('creds', [])
            if args.user:
                creds = [(args.user, args.password)] + creds
            targets.append({'ip': d['ip'], 'creds': creds or DEFAULT_CREDS})

    elif args.file:
        try:
            ips = [l.strip() for l in open(args.file)
                   if l.strip() and not l.startswith('#')]
        except OSError as e:
            print(f"[!] {e}"); sys.exit(1)
        creds = [(args.user, args.password)] if args.user else DEFAULT_CREDS
        targets = [{'ip': ip, 'creds': creds} for ip in ips]

    elif args.host:
        creds = [(args.user, args.password)] if args.user else DEFAULT_CREDS
        targets = [{'ip': ip, 'creds': creds} for ip in expand_hosts(args.host)]

    else:
        parser.error('specify --host, --file, or --discover')

    if not targets:
        print("[!] No targets."); sys.exit(0)

    action_parts = []
    if args.dry_run:
        action_parts.append('dry-run (read only)')
    else:
        if args.encoder:
            action_parts.append(f'encoder → {args.encoder}')
        if args.main_bitrate is not None:
            action_parts.append(f'main BR → {args.main_bitrate} kbps')
        if args.sub_bitrate is not None:
            action_parts.append(f'sub BR → {args.sub_bitrate} kbps')
        if args.main_framerate is not None:
            action_parts.append(f'main FPS → {args.main_framerate}')
        if args.sub_framerate is not None:
            action_parts.append(f'sub FPS → {args.sub_framerate}')
    action = ', '.join(action_parts) if action_parts else 'read only'

    print(f"[*] Targets : {len(targets)}")
    print(f"[*] Action  : {action}")
    print(f"[*] Stream  : {args.stream}")
    print(f"[*] Threads : {args.threads}")
    print()

    # ── Process ───────────────────────────────────────────────────────────────
    results = []

    def run(t):
        return process_camera(
            ip             = t['ip'],
            credentials    = t['creds'],
            target         = args.encoder or '',
            stream         = args.stream,
            dry_run        = args.dry_run,
            force          = args.force,
            verbose        = args.verbose,
            timeout        = args.timeout,
            main_bitrate   = args.main_bitrate,
            sub_bitrate    = args.sub_bitrate,
            main_framerate = args.main_framerate,
            sub_framerate  = args.sub_framerate,
        )

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(run, t): t for t in targets}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            # Live progress indicator (just IP + outcome, detail is in the summary table)
            if not r['ok']:
                print(f"  [{r['ip']}]  FAILED — {r['error']}")
            elif r['skipped']:
                print(f"  [{r['ip']}]  already set, skipping")
            else:
                tag = '(dry)' if args.dry_run else 'changed'
                print(f"  [{r['ip']}]  {tag}")

    # ── Summary ───────────────────────────────────────────────────────────────
    changed = [r for r in results if r['ok'] and not r['skipped']]
    skipped = [r for r in results if r['skipped']]
    failed  = [r for r in results if not r['ok']]

    # Sort summary by IP
    results_sorted = sorted(results, key=lambda r: ipaddress.ip_address(r['ip']))

    print(f"\n{'─'*W}")
    print(f"  Done.  Changed: {len(changed)}  Already set: {len(skipped)}"
          f"  Failed: {len(failed)}")
    print(f"{'─'*W}")

    def fmt_cell(prev, new):
        """'prev→new' if changed, else just the value, else '—'."""
        prev = str(prev) if prev else '—'
        if new is not None and str(new) != prev:
            return f"{prev}→{new}"
        return prev

    # Column widths
    CW = dict(ip=18, status=8, main=11, sub=11, mbr=10, sbr=10, mfr=8, sfr=8)
    hdr = (f"  {'IP':<{CW['ip']}}  {'Status':<{CW['status']}}"
           f"  {'Main codec':<{CW['main']}}  {'Sub codec':<{CW['sub']}}"
           f"  {'Main BR':>{CW['mbr']}}  {'Sub BR':>{CW['sbr']}}"
           f"  {'Main FPS':>{CW['mfr']}}  {'Sub FPS':>{CW['sfr']}}")
    sep = (f"  {'─'*CW['ip']}  {'─'*CW['status']}"
           f"  {'─'*CW['main']}  {'─'*CW['sub']}"
           f"  {'─'*CW['mbr']}  {'─'*CW['sbr']}"
           f"  {'─'*CW['mfr']}  {'─'*CW['sfr']}")
    print()
    print(hdr)
    print(sep)

    for r in results_sorted:
        ip = r['ip']
        if not r['ok']:
            status     = 'FAIL'
            main_codec = sub_codec = main_br = sub_br = main_fr = sub_fr = '—'
            warning    = r['error']
        elif r['skipped']:
            status     = 'same'
            main_codec = r['prev_main']
            sub_codec  = r['prev_sub']
            main_br    = r.get('prev_main_br') or '—'
            sub_br     = r.get('prev_sub_br')  or '—'
            main_fr    = r.get('prev_main_fr') or '—'
            sub_fr     = r.get('prev_sub_fr')  or '—'
            warning    = ''
        else:
            status = '(dry)' if args.dry_run else 'OK'
            new_main = args.encoder if args.encoder and args.stream in ('main', 'both') else None
            new_sub  = args.encoder if args.encoder and args.stream in ('sub',  'both') else None
            main_codec = fmt_cell(r['prev_main'],              new_main)
            sub_codec  = fmt_cell(r['prev_sub'],               new_sub)
            main_br    = fmt_cell(r.get('prev_main_br') or '—', args.main_bitrate)
            sub_br     = fmt_cell(r.get('prev_sub_br')  or '—', args.sub_bitrate)
            main_fr    = fmt_cell(r.get('prev_main_fr') or '—', args.main_framerate)
            sub_fr     = fmt_cell(r.get('prev_sub_fr')  or '—', args.sub_framerate)
            warning    = r.get('warning', '')

        row = (f"  {ip:<{CW['ip']}}  {status:<{CW['status']}}"
               f"  {main_codec:<{CW['main']}}  {sub_codec:<{CW['sub']}}"
               f"  {main_br:>{CW['mbr']}}  {sub_br:>{CW['sbr']}}"
               f"  {main_fr:>{CW['mfr']}}  {sub_fr:>{CW['sfr']}}")
        print(row)
        if warning:
            print(f"    ⚠  {warning}")

    print()


if __name__ == '__main__':
    main()

