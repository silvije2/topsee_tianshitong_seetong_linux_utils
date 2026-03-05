#!/usr/bin/env python3
"""
Topsee / Tianshitong — motion event subscriber
===============================================
Connects to the camera TCP SDK (port 8091), logs in, subscribes to all alarm
events, and prints a line whenever a motion-start event arrives.  Reconnects
automatically on connection loss.

Authors: Claude (Anthropic) — protocol reverse engineering from
    LinuxNetSDK_Release_x86_V22_20140529 binary analysis (disassembly of
    libNetSDK.so, frame structure, XML protocol, UDP response flow, ONVIF
    integration), full implementation

Contributors (silvije2) — live packet capture validation, tcpdump-based
    protocol debugging, ONVIF script reference, firewall diagnostics,
    feature direction

Usage:
    python3 topsee_motion.py
    python3 topsee_motion.py --ip 192.168.2.22 --user admin --password 123456
"""

import argparse
import re
import socket
import struct
import time

# ── defaults (override via CLI args) ─────────────────────────────────────────
DEFAULT_IP       = ''
DEFAULT_PORT     = 8091
DEFAULT_USER     = 'admin'
DEFAULT_PASSWORD = '123456'
COOLDOWN_S       = 4      # minimum seconds between printed alerts
RECONNECT_DELAY  = 5      # seconds to wait before reconnecting
KEEPALIVE_EVERY  = 15     # socket timeout; a heartbeat is sent on each expiry
W = 68

# ── protocol helpers ──────────────────────────────────────────────────────────
MAGIC = bytes.fromhex('58915851')

USAGE = """
Usage:
  sudo python3 topsee_motion.py --ip 192.168.1.2 --user admin --password 123456 --cooldown 5
"""

def _frame(xml: str) -> bytes:
    """Encode an XML string into a framed SDK packet: magic + LE-length + GB2312 body."""
    body = xml.encode('gb2312')
    return MAGIC + struct.pack('<I', len(body)) + body


def _recv_frame(sock: socket.socket) -> str:
    """
    Read one complete XML_TOPSEE response from the socket.
    Discards the 8-byte magic+length header, returns the decoded XML string.
    """
    buf = b''
    while b'</XML_TOPSEE>' not in buf:
        chunk = sock.recv(8192)
        if not chunk:
            raise ConnectionError('connection closed by camera')
        buf += chunk
    # Strip leading magic+length (8 bytes) if present, then decode
    if buf[:4] == MAGIC:
        buf = buf[8:]
    return buf.decode('gb2312', errors='replace')


def _xml_login(user: str, password: str) -> str:
    return (
        '<?xml version="1.0" encoding="GB2312" ?>'
        '<XML_TOPSEE>'
        '<MESSAGE_HEADER Msg_type="USER_AUTH_MESSAGE"'
        ' Msg_code="CMD_USER_AUTH" Msg_flag="0"/>'
        '<MESSAGE_BODY>'
        f'<USER_AUTH_PARAM Username="{user}" Password="{password}"'
        ' AuthMethod="1"/>'
        '</MESSAGE_BODY>'
        '</XML_TOPSEE>'
    )


def _xml_subscribe(sid: str) -> str:
    return (
        '<?xml version="1.0" encoding="GB2312" ?>'
        '<XML_TOPSEE>'
        '<MESSAGE_HEADER Msg_type="ALARM_MESSAGE"'
        ' Msg_code="CMD_ALARM_SUBSCRIBE" Msg_flag="0"/>'
        '<MESSAGE_BODY>'
        f'<ALARM_SUBSCRIBE_PARAM Sessionid="{sid}" Action="1" AlarmType="all"/>'
        '</MESSAGE_BODY>'
        '</XML_TOPSEE>'
    )


def _xml_keepalive(sid: str) -> str:
    return (
        '<?xml version="1.0" encoding="GB2312" ?>'
        '<XML_TOPSEE>'
        '<MESSAGE_HEADER Msg_type="KEEP_ALIVE_MESSAGE"'
        ' Msg_code="CMD_KEEP_ALIVE" Msg_flag="0"/>'
        f'<MESSAGE_BODY Sessionid="{sid}"/>'
        '</XML_TOPSEE>'
    )


# ── session ───────────────────────────────────────────────────────────────────
def login(sock: socket.socket, user: str, password: str) -> str:
    """Send login frame, parse and return the session ID."""
    sock.sendall(_frame(_xml_login(user, password)))
    response = _recv_frame(sock)
    m = re.search(r'Sessionid\s*=\s*["\']([A-Za-z0-9_]+)["\']', response)
    if not m:
        raise ValueError(f'login failed — no Sessionid in response:\n{response}')
    return m.group(1)


def subscribe(sock: socket.socket, sid: str) -> None:
    """Subscribe to all alarm events for this session."""
    sock.sendall(_frame(_xml_subscribe(sid)))


# ── event loop ────────────────────────────────────────────────────────────────
def monitor(ip: str, port: int, user: str, password: str,
            cooldown: float = COOLDOWN_S) -> None:
    """
    Connect, log in, subscribe, and loop forever printing motion events.
    Reconnects automatically on any error.
    """
    last_alert = 0.0

    while True:
        try:
            print(f'[*] Connecting to {ip}:{port}…')
            with socket.create_connection((ip, port), timeout=10) as sock:
                print('[*] Logging in…')
                sid = login(sock, user, password)
                print(f'[*] Session: {sid}')

                subscribe(sock, sid)
                print('[*] Subscribed — monitoring for motion events')
                print('    (Ctrl-C to stop)\n')

                sock.settimeout(KEEPALIVE_EVERY)

                while True:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            raise ConnectionError('connection closed by camera')

                        decoded = data.decode('gb2312', errors='replace')

                        if 'CMD_REPORT_ALARM' in decoded:
                            m = re.search(r'Alarm_flag="(\d)"', decoded)
                            if m and m.group(1) == '1':
                                now = time.time()
                                if now - last_alert >= cooldown:
                                    ts = time.strftime('%H:%M:%S')
                                    print(f'[{ts}]  🔥  motion detected  ({ip})')
                                    last_alert = now

                    except socket.timeout:
                        sock.sendall(_frame(_xml_keepalive(sid)))

        except KeyboardInterrupt:
            print('\n[*] Stopped.')
            return
        except Exception as e:
            print(f'[!] {e} — reconnecting in {RECONNECT_DELAY}s…')
            time.sleep(RECONNECT_DELAY)


# ── entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    print("=" * W)
    print("  Topsee / Tianshitong motion detect")
    print("  Authors: Claude (Anthropic), silvije2 (https://github.com/silvije2)")
    print("=" * W)
    print(USAGE)

    ap = argparse.ArgumentParser(description='Topsee motion event monitor')
    ap.add_argument('--ip',       default=DEFAULT_IP,       help='Camera IP')
    ap.add_argument('--port',     default=DEFAULT_PORT,     type=int)
    ap.add_argument('--user',     default=DEFAULT_USER)
    ap.add_argument('--password', default=DEFAULT_PASSWORD)
    ap.add_argument('--cooldown', default=COOLDOWN_S,       type=float,
                    help='Minimum seconds between alerts (default: %(default)s)')
    args = ap.parse_args()

    monitor(args.ip, args.port, args.user, args.password, args.cooldown)


if __name__ == '__main__':
    main()

