#!/usr/bin/env python3
"""
netmap.py — Pure-Python network reconnaissance tool
Inspired by nmap (https://nmap.org) and masscan (https://github.com/robertdavidgraham/masscan)

Author : G4MEOVER18
License: MIT
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import queue
import random
import re
import select
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Terminal colour helpers (no third-party deps)
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"
DIM    = "\033[2m"

def _supports_color() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

def c(text: str, *codes: str) -> str:
    if not USE_COLOR:
        return text
    return "".join(codes) + text + RESET

# ---------------------------------------------------------------------------
# Well-known ports / service names
# ---------------------------------------------------------------------------

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 179, 194,
    389, 443, 445, 465, 500, 512, 513, 514, 515, 587, 631, 636, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2121, 2222, 2375, 3306, 3389, 3690,
    4444, 5000, 5432, 5900, 5901, 6379, 6443, 6667, 7000, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 10000,
    11211, 27017, 27018, 28017, 50000, 50070, 61616,
    # fill to 100 with common ones
    20, 69, 79, 88, 102, 113, 137, 138, 161, 162, 264, 381, 383, 411, 412,
    427, 444, 873, 902, 981, 1080, 1194,
]
TOP_100_PORTS = sorted(set(TOP_100_PORTS))[:100]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1080, 1194, 1433, 1521, 1723, 2049, 2121, 2222, 2375, 3306, 3389, 3690,
    4444, 5000, 5432, 5900, 5901, 6379, 6443, 6667, 7000, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999, 10000,
    11211, 27017, 27018, 28017, 50000, 50070, 61616,
]
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))[:1000]

PORT_SERVICE_NAMES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    194: "irc", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 500: "isakmp", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2121: "ftp-proxy", 2222: "ssh-alt",
    2375: "docker", 3306: "mysql", 3389: "ms-wbt-server", 3690: "svn",
    4444: "krb524", 5000: "upnp", 5432: "postgresql", 5900: "vnc",
    5901: "vnc-1", 6379: "redis", 6443: "kubernetes-api",
    6667: "irc", 7000: "afs3-fileserver", 7001: "afs3-callback",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "blackice-icecap", 8443: "https-alt", 8888: "sun-answerbook",
    9000: "cslistener", 9090: "zeus-admin", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 9418: "git", 9999: "abyss",
    10000: "snet-sensor-mgmt", 11211: "memcache",
    27017: "mongodb", 27018: "mongodb-shard", 28017: "mongodb-web",
    50000: "db2", 50070: "hadoop-namenode", 61616: "activemq",
    5353: "mdns", 5355: "llmnr", 49152: "unknown", 554: "rtsp",
    5060: "sip", 5061: "sips",
}

# ---------------------------------------------------------------------------
# Banner probes — what to send to trigger a banner/response
# ---------------------------------------------------------------------------

BANNER_PROBES: Dict[int, bytes] = {
    21:    b"",                                         # FTP sends banner on connect
    22:    b"",                                         # SSH sends banner on connect
    23:    b"\xff\xfd\x18",                             # Telnet option negotiation
    25:    b"EHLO netmap\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",                                         # POP3 sends banner on connect
    143:   b"",                                         # IMAP sends banner on connect
    443:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    445:   b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8",
    3306:  b"",                                         # MySQL sends greeting
    5432:  b"",                                         # PG sends auth request
    6379:  b"PING\r\n",
    27017: b"\x3a\x00\x00\x00\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
           b"\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00"
           b"\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61"
           b"\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
}

# ---------------------------------------------------------------------------
# Service detection patterns (regex on banner bytes → service label)
# ---------------------------------------------------------------------------

SERVICE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(rb"SSH-\d+\.\d+",                       re.I), "ssh"),
    (re.compile(rb"220[\s-].*ftp",                       re.I), "ftp"),
    (re.compile(rb"220[\s-].*smtp|220[\s-].*mail|ehlo",  re.I), "smtp"),
    (re.compile(rb"\+OK",                                re.I), "pop3"),
    (re.compile(rb"\* OK",                               re.I), "imap"),
    (re.compile(rb"HTTP/\d\.\d",                         re.I), "http"),
    (re.compile(rb"<title",                              re.I), "http"),
    (re.compile(rb"mysql|mariadb",                       re.I), "mysql"),
    (re.compile(rb"postgresql|pg_hba",                   re.I), "postgresql"),
    (re.compile(rb"\+PONG",                              re.I), "redis"),
    (re.compile(rb"-ERR.*redis",                         re.I), "redis"),
    (re.compile(rb"mongod",                              re.I), "mongodb"),
    (re.compile(rb"elastic",                             re.I), "elasticsearch"),
    (re.compile(rb"\x03\xef",                            re.I), "rdp"),
    (re.compile(rb"smb|netbios|samba",                   re.I), "smb"),
    (re.compile(rb"vnc|rfb \d+\.\d+",                    re.I), "vnc"),
    (re.compile(rb"rtsp/\d+\.\d+",                       re.I), "rtsp"),
    (re.compile(rb"sip/\d+\.\d+|via: sip",              re.I), "sip"),
    (re.compile(rb"220[\s-].*ftp|530|150",               re.I), "ftp"),
    (re.compile(rb"telnet|\xff\xfb|\xff\xfd",            re.I), "telnet"),
]

OS_BANNER_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(rb"ubuntu|debian|kali|centos|fedora|rhel|arch linux", re.I), "Linux"),
    (re.compile(rb"windows|microsoft|win32|iis",                       re.I), "Windows"),
    (re.compile(rb"cisco ios|cisco nx-os",                             re.I), "Cisco"),
    (re.compile(rb"freebsd|openbsd|netbsd",                            re.I), "BSD"),
    (re.compile(rb"macos|darwin|os x",                                 re.I), "macOS"),
    (re.compile(rb"vmware",                                            re.I), "VMware"),
    (re.compile(rb"synology|dsm",                                      re.I), "Synology DSM"),
    (re.compile(rb"fortios|fortigate",                                 re.I), "FortiOS"),
    (re.compile(rb"junos",                                             re.I), "JunOS"),
    (re.compile(rb"openwrt",                                           re.I), "OpenWrt"),
]

# ---------------------------------------------------------------------------
# Timing profiles  (connect_timeout, inter-probe delay, max_threads_multiplier)
# ---------------------------------------------------------------------------

TIMING_PROFILES = {
    1: dict(connect_timeout=5.0,  delay=0.5,  thread_mult=0.1),   # paranoid/slow
    2: dict(connect_timeout=4.0,  delay=0.2,  thread_mult=0.3),   # polite
    3: dict(connect_timeout=2.0,  delay=0.05, thread_mult=0.7),   # normal (default)
    4: dict(connect_timeout=1.0,  delay=0.01, thread_mult=1.0),   # aggressive
    5: dict(connect_timeout=0.3,  delay=0.0,  thread_mult=1.0),   # insane
}

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate: float):
        self._rate  = rate           # packets per second (0 = unlimited)
        self._lock  = threading.Lock()
        self._last  = time.monotonic()
        self._errors = 0

    def wait(self):
        if self._rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            gap = 1.0 / self._rate
            elapsed = now - self._last
            if elapsed < gap:
                time.sleep(gap - elapsed)
            self._last = time.monotonic()

    def record_error(self):
        with self._lock:
            self._errors += 1
            if self._errors > 20 and self._rate > 10:
                self._rate *= 0.8
                self._errors = 0


# ---------------------------------------------------------------------------
# Core scan functions
# ---------------------------------------------------------------------------

def tcp_scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> bytes:
    """Connect, optionally send a probe, and return up to 4096 bytes."""
    probe = BANNER_PROBES.get(port, b"")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if probe:
                s.sendall(probe)
            # Give service time to respond
            time.sleep(0.15)
            data = b""
            s.settimeout(1.5)
            try:
                while len(data) < 4096:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            return data
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b""


def detect_service(port: int, banner: bytes) -> str:
    """Return a service name string based on port + banner content."""
    for pattern, name in SERVICE_PATTERNS:
        if pattern.search(banner):
            return name
    # Fall back to well-known port name
    return PORT_SERVICE_NAMES.get(port, "unknown")


def os_fingerprint(host: str, open_ports: List[int], banners: Dict[int, bytes]) -> str:
    """Heuristic OS detection from banners + TTL."""
    # 1) Try banner-based detection first
    all_banner_data = b" ".join(banners.values())
    for pattern, os_name in OS_BANNER_PATTERNS:
        if pattern.search(all_banner_data):
            return os_name

    # 2) Try TTL-based detection via ICMP echo (Windows only — needs admin)
    #    Fall back to TCP connect TTL heuristic
    ttl = _probe_ttl(host)
    if ttl is not None:
        if ttl <= 64:
            return "Linux/Unix (TTL<=64)"
        elif ttl <= 128:
            return "Windows (TTL<=128)"
        elif ttl <= 255:
            return "Cisco/Network device (TTL<=255)"

    # 3) Port-based heuristics
    if 3389 in open_ports or 135 in open_ports:
        return "Windows (likely)"
    if 22 in open_ports and 111 in open_ports:
        return "Linux/Unix (likely)"
    if 22 in open_ports:
        return "Linux/Unix or network device"

    return "Unknown"


def _probe_ttl(host: str) -> Optional[int]:
    """Attempt to read the TTL of a TCP SYN-ACK response (best-effort)."""
    try:
        # Use a raw connect and check the socket TTL option if available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, 80))
            # IP_TTL on Linux; on Windows SOL_SOCKET / SO_RCVTIMEO
            try:
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                return ttl
            except (AttributeError, OSError):
                return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# UDP probes
# ---------------------------------------------------------------------------

UDP_PROBES: Dict[int, bytes] = {
    53:  (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07version\x04bind\x00\x00\x10\x00\x03"),   # DNS version.bind query
    123: (b"\x1b" + b"\x00" * 47),                        # NTP client request
    161: (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
          b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b"
          b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),  # SNMP v1 get-request
}

def udp_probe(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, bytes]:
    """Send a UDP probe and return (got_response, response_data)."""
    probe = UDP_PROBES.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            data, _ = s.recvfrom(1024)
            return True, data
    except socket.timeout:
        return False, b""
    except OSError:
        return False, b""


# ---------------------------------------------------------------------------
# ICMP ping (best-effort, falls back to TCP probe)
# ---------------------------------------------------------------------------

def ping_host(host: str, timeout: float = 1.0) -> bool:
    """Return True if host appears to be alive."""
    # Try a quick TCP connect to common ports first (works without raw sockets)
    for port in (80, 443, 22, 445, 8080):
        if tcp_scan_port(host, port, timeout=0.5):
            return True
    # Try ICMP ping on supported platforms
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host],
                capture_output=True, timeout=timeout + 1
            )
            return result.returncode == 0
        else:
            import subprocess
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), host],
                capture_output=True, timeout=timeout + 1
            )
            return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Script engine
# ---------------------------------------------------------------------------

def run_script(script_name: str, host: str, port: int,
               banner: bytes, timeout: float = 3.0) -> Optional[str]:
    """Run a named script and return a string result or None."""
    name = script_name.lower()

    if name == "http-title":
        return _script_http_title(host, port, timeout)

    if name == "ssh-banner":
        return _script_ssh_banner(banner)

    if name == "ftp-anon":
        return _script_ftp_anon(host, port, timeout)

    if name == "smb-os":
        return _script_smb_os(host, timeout)

    return None


def _script_http_title(host: str, port: int, timeout: float) -> Optional[str]:
    """HTTP GET / and extract <title>.</title>."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netmap/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            data = b""
            s.settimeout(2.0)
            try:
                while len(data) < 8192:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
        m = re.search(rb"<title[^>]*>(.*?)</title>", data, re.I | re.S)
        if m:
            title = m.group(1).decode("utf-8", errors="replace").strip()
            title = re.sub(r"\s+", " ", title)
            return f"title: {title}"
        return "http-title: no title found"
    except Exception as e:
        return f"http-title error: {e}"


def _script_ssh_banner(banner: bytes) -> Optional[str]:
    if not banner:
        return None
    try:
        line = banner.split(b"\n")[0].decode("utf-8", errors="replace").strip()
        return f"ssh-banner: {line}"
    except Exception:
        return None


def _script_ftp_anon(host: str, port: int, timeout: float) -> Optional[str]:
    """Test anonymous FTP login."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.settimeout(2.0)
            banner = b""
            try:
                banner = s.recv(1024)
            except socket.timeout:
                pass
            s.sendall(b"USER anonymous\r\n")
            time.sleep(0.3)
            resp1 = b""
            try:
                resp1 = s.recv(1024)
            except socket.timeout:
                pass
            s.sendall(b"PASS anonymous@netmap.local\r\n")
            time.sleep(0.5)
            resp2 = b""
            try:
                resp2 = s.recv(1024)
            except socket.timeout:
                pass
            if b"230" in resp2:
                return "ftp-anon: ANONYMOUS LOGIN ALLOWED"
            elif b"530" in resp2:
                return "ftp-anon: anonymous login denied"
            else:
                code = resp2[:3].decode("ascii", errors="replace")
                return f"ftp-anon: response {code}"
    except Exception as e:
        return f"ftp-anon error: {e}"


def _script_smb_os(host: str, timeout: float) -> Optional[str]:
    """Attempt NetBIOS Name Service query for OS info."""
    # Send NetBIOS NS query
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # NBNS query: transaction id 0x1234, flags QUERY+RD, QNAME = *
            query = (b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                     b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
                     b"\x00\x21\x00\x01")
            s.sendto(query, (host, 137))
            data, _ = s.recvfrom(1024)
            if len(data) >= 57:
                names = []
                num_names = data[56]
                offset = 57
                for _ in range(num_names):
                    if offset + 18 > len(data):
                        break
                    raw_name = data[offset:offset+15].decode("ascii", errors="replace").strip()
                    flags = struct.unpack(">H", data[offset+16:offset+18])[0]
                    if raw_name:
                        names.append(raw_name)
                    offset += 18
                if names:
                    return f"smb-os: NetBIOS names: {', '.join(names)}"
        return "smb-os: no NetBIOS response"
    except socket.timeout:
        return "smb-os: no response (timeout)"
    except Exception as e:
        return f"smb-os error: {e}"


# ---------------------------------------------------------------------------
# Traceroute (TTL-based via TCP)
# ---------------------------------------------------------------------------

def traceroute(host: str, port: int = 80, max_hops: int = 30,
               timeout: float = 2.0) -> List[Tuple[int, str, float]]:
    """
    TTL-based traceroute using TCP SYN probes.
    Returns list of (hop, ip_or_*, rtt_ms).
    NOTE: Sending raw sockets requires elevated privileges on most systems.
          This implementation uses a best-effort approach with ICMP where available,
          falling back to a simple display.
    """
    hops: List[Tuple[int, str, float]] = []
    try:
        dest_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return []

    for ttl in range(1, max_hops + 1):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
        except PermissionError:
            # No raw socket access — return what we have with a note
            hops.append((ttl, "[raw socket requires root/admin]", 0.0))
            break

        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                      socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            send_sock.settimeout(timeout)

            t_start = time.monotonic()
            send_sock.sendto(b"NETMAP", (dest_ip, port))
            try:
                data, addr = recv_sock.recvfrom(512)
                rtt = (time.monotonic() - t_start) * 1000
                hop_ip = addr[0]
                hops.append((ttl, hop_ip, rtt))
                if hop_ip == dest_ip:
                    break
            except socket.timeout:
                hops.append((ttl, "*", 0.0))
        except Exception:
            hops.append((ttl, "*", 0.0))
        finally:
            try:
                send_sock.close()
            except Exception:
                pass
            try:
                recv_sock.close()
            except Exception:
                pass

    return hops


# ---------------------------------------------------------------------------
# Host scanner — orchestrates the scan of one host
# ---------------------------------------------------------------------------

class PortResult:
    __slots__ = ("port", "state", "service", "banner", "os_hint", "script_output")

    def __init__(self, port: int, state: str, service: str = "",
                 banner: bytes = b"", os_hint: str = "", script_output: str = ""):
        self.port          = port
        self.state         = state
        self.service       = service
        self.banner        = banner
        self.os_hint       = os_hint
        self.script_output = script_output


def scan_host(host: str, ports: List[int], *,
              threads: int = 100,
              connect_timeout: float = 1.0,
              banner_grab: bool = True,
              scripts: Optional[List[str]] = None,
              udp_ports: Optional[List[int]] = None,
              rate_limiter: Optional[RateLimiter] = None,
              timing_delay: float = 0.0) -> Tuple[str, List[PortResult], str]:
    """
    Scan a single host across the given port list.
    Returns (resolved_hostname, open_port_results, os_guess).
    """
    # Resolve hostname once
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return host, [], "DNS resolution failed"

    open_results: List[PortResult] = []
    lock = threading.Lock()

    def _scan_one(port: int):
        if rate_limiter:
            rate_limiter.wait()
        if timing_delay > 0:
            time.sleep(timing_delay * random.uniform(0.5, 1.5))

        is_open = tcp_scan_port(ip, port, timeout=connect_timeout)
        if not is_open:
            if rate_limiter:
                rate_limiter.record_error()
            return

        banner  = b""
        service = PORT_SERVICE_NAMES.get(port, "unknown")

        if banner_grab:
            banner  = grab_banner(ip, port, timeout=connect_timeout + 1.0)
            service = detect_service(port, banner)

        script_out = ""
        if scripts:
            parts = []
            for sc in scripts:
                res = run_script(sc, ip, port, banner, timeout=connect_timeout + 2.0)
                if res:
                    parts.append(res)
            script_out = " | ".join(parts)

        result = PortResult(port, "open", service, banner, "", script_out)
        with lock:
            open_results.append(result)

    # TCP scan
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        list(executor.map(_scan_one, ports))

    # UDP scan
    if udp_ports:
        for port in udp_ports:
            got_resp, resp_data = udp_probe(ip, port)
            if got_resp:
                svc = detect_service(port, resp_data)
                open_results.append(PortResult(port, "open|filtered", svc, resp_data))

    open_results.sort(key=lambda r: r.port)

    # OS fingerprint
    all_banners  = {r.port: r.banner for r in open_results}
    open_port_ns = [r.port for r in open_results]
    os_guess     = os_fingerprint(ip, open_port_ns, all_banners)

    return ip, open_results, os_guess


# ---------------------------------------------------------------------------
# Subnet scanner
# ---------------------------------------------------------------------------

def scan_subnet(cidr: str, ports: List[int], *,
                threads: int = 100,
                connect_timeout: float = 1.0,
                banner_grab: bool = True,
                scripts: Optional[List[str]] = None,
                udp_ports: Optional[List[int]] = None,
                rate_limiter: Optional[RateLimiter] = None,
                timing_delay: float = 0.0,
                ping_first: bool = True,
                host_threads: int = 20) -> List[Tuple[str, List[PortResult], str]]:
    """
    Scan an entire subnet.  First discovers live hosts, then port-scans each.
    Returns list of (ip, open_ports, os_guess).
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(c(f"[!] Invalid CIDR: {e}", RED))
        return []

    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        return []

    print(c(f"[*] Subnet {cidr}: {len(hosts)} hosts to probe", CYAN))

    # Phase 1: host discovery
    if ping_first:
        live_hosts: List[str] = []
        lock = threading.Lock()

        def _check_alive(h: str):
            if ping_host(h, timeout=1.0):
                with lock:
                    live_hosts.append(h)

        print(c("[*] Host discovery phase...", CYAN))
        with concurrent.futures.ThreadPoolExecutor(max_workers=host_threads) as ex:
            list(ex.map(_check_alive, hosts))

        print(c(f"[+] {len(live_hosts)} live host(s) found", GREEN))
    else:
        live_hosts = hosts

    if not live_hosts:
        return []

    # Phase 2: port scan each live host
    results: List[Tuple[str, List[PortResult], str]] = []
    lock2 = threading.Lock()

    def _scan_one_host(h: str):
        ip, ports_res, os_g = scan_host(
            h, ports, threads=threads,
            connect_timeout=connect_timeout,
            banner_grab=banner_grab,
            scripts=scripts,
            udp_ports=udp_ports,
            rate_limiter=rate_limiter,
            timing_delay=timing_delay,
        )
        if ports_res:
            with lock2:
                results.append((ip, ports_res, os_g))
            _print_host_result(ip, ports_res, os_g)

    with concurrent.futures.ThreadPoolExecutor(max_workers=host_threads) as ex:
        list(ex.map(_scan_one_host, live_hosts))

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _banner_preview(banner: bytes, max_len: int = 60) -> str:
    try:
        text = banner.decode("utf-8", errors="replace")
    except Exception:
        return repr(banner[:max_len])
    text = re.sub(r"[\r\n\t]+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text


def _print_host_result(ip: str, results: List[PortResult], os_guess: str):
    """Pretty-print results for one host to stdout."""
    print()
    print(c(f"Host: {ip}", BOLD + CYAN))
    print(c(f"OS  : {os_guess}", YELLOW))
    print(c(f"{'PORT':<8}{'STATE':<12}{'SERVICE':<18}{'BANNER/INFO'}", BOLD))
    print(c("-" * 72, DIM))
    for r in results:
        state_color = GREEN if r.state == "open" else YELLOW
        banner_info = _banner_preview(r.banner)
        if r.script_output:
            banner_info = r.script_output if r.script_output else banner_info
        line = f"{r.port:<8}{r.state:<12}{r.service:<18}{banner_info}"
        print(c(str(r.port), state_color) + f"       {c(r.state, state_color):<12}"
              f"{r.service:<18}{c(banner_info, DIM)}")
    print(c("-" * 72, DIM))


def format_normal(scan_time: float, target: str,
                  all_results: List[Tuple[str, List[PortResult], str]]) -> str:
    lines = []
    lines.append(f"# netmap scan report")
    lines.append(f"# Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"# Target  : {target}")
    lines.append(f"# Elapsed : {scan_time:.2f}s")
    lines.append("")
    for ip, results, os_guess in all_results:
        lines.append(f"Host: {ip}")
        lines.append(f"OS  : {os_guess}")
        for r in results:
            banner_short = _banner_preview(r.banner)
            info = r.script_output or banner_short
            lines.append(f"  {r.port}/tcp  {r.state:<14} {r.service:<18} {info}")
        lines.append("")
    lines.append(f"# {sum(len(r) for _, r, _ in all_results)} open port(s) found in {scan_time:.2f}s")
    return "\n".join(lines)


def format_json(scan_time: float, target: str,
                all_results: List[Tuple[str, List[PortResult], str]]) -> str:
    data = {
        "meta": {
            "tool"    : "netmap",
            "target"  : target,
            "date"    : datetime.now().isoformat(),
            "elapsed" : round(scan_time, 3),
        },
        "hosts": []
    }
    for ip, results, os_guess in all_results:
        host_obj = {
            "ip"    : ip,
            "os"    : os_guess,
            "ports" : []
        }
        for r in results:
            host_obj["ports"].append({
                "port"   : r.port,
                "state"  : r.state,
                "service": r.service,
                "banner" : r.banner.decode("utf-8", errors="replace")[:200],
                "scripts": r.script_output,
            })
        data["hosts"].append(host_obj)
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_grepable(scan_time: float, target: str,
                    all_results: List[Tuple[str, List[PortResult], str]]) -> str:
    lines = []
    lines.append(f"# netmap grepable output — {datetime.now().isoformat()}")
    for ip, results, os_guess in all_results:
        ports_str = ", ".join(
            f"{r.port}/open/tcp//{r.service}//" for r in results
        )
        lines.append(f"Host: {ip} ()  Ports: {ports_str}  OS: {os_guess}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> List[int]:
    """Parse a port spec like '22,80,443,1000-2000' into a sorted list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo_i, hi_i = int(lo.strip()), int(hi.strip())
                if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                    raise ValueError
                ports.update(range(lo_i, hi_i + 1))
            except ValueError:
                print(c(f"[!] Invalid port range: {part}", RED), file=sys.stderr)
                sys.exit(1)
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                print(c(f"[!] Invalid port: {part}", RED), file=sys.stderr)
                sys.exit(1)
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmap",
        description=(
            "netmap — Pure-Python network reconnaissance tool\n"
            "Inspired by nmap (https://nmap.org) and\n"
            "masscan (https://github.com/robertdavidgraham/masscan)\n\n"
            "LEGAL NOTICE: Use only on networks/systems you own or have\n"
            "explicit written permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("target", nargs="+",
                   help="Host(s) or CIDR subnet(s) to scan (e.g. 192.168.1.1 or 10.0.0.0/24)")

    port_grp = p.add_mutually_exclusive_group()
    port_grp.add_argument("--ports", "-p", metavar="SPEC",
                          help="Port specification: 22,80,443 or 1-1024 (default: top 1000)")
    port_grp.add_argument("--top100",  action="store_true", help="Scan top 100 common ports")
    port_grp.add_argument("--top1000", action="store_true", help="Scan top 1000 common ports (default)")

    p.add_argument("--threads", "-t", type=int, default=100, metavar="N",
                   help="Number of concurrent scan threads (1-500, default: 100)")
    p.add_argument("--timeout", type=float, default=None, metavar="SEC",
                   help="Per-port connect timeout in seconds (overrides timing profile)")
    p.add_argument("--rate", type=float, default=0, metavar="PPS",
                   help="Max packets per second (0 = unlimited)")
    p.add_argument("--no-banner", action="store_true",
                   help="Skip banner grabbing (faster, less info)")
    p.add_argument("--scripts", "-sC", metavar="NAMES",
                   help="Comma-separated scripts: http-title,ssh-banner,ftp-anon,smb-os")
    p.add_argument("--udp", "-sU", metavar="PORTS",
                   help="UDP ports to probe (e.g. 53,123,161)")
    p.add_argument("--traceroute", action="store_true",
                   help="Perform TTL-based traceroute to each target")
    p.add_argument("--no-ping", action="store_true",
                   help="Skip host discovery (scan all hosts in subnet)")
    p.add_argument("-T", dest="timing", type=int, default=3, choices=range(1, 6),
                   metavar="{1..5}",
                   help="Timing template: T1=slow/stealth ... T5=insane/fast (default: T3)")

    out_grp = p.add_argument_group("Output")
    out_grp.add_argument("-oN", metavar="FILE", help="Normal output to file")
    out_grp.add_argument("-oJ", metavar="FILE", help="JSON output to file")
    out_grp.add_argument("-oG", metavar="FILE", help="Grepable output to file")
    out_grp.add_argument("-v", "--verbose", action="store_true",
                         help="Verbose output (show closed/filtered ports)")

    return p


# ---------------------------------------------------------------------------
# Banner / intro
# ---------------------------------------------------------------------------

BANNER = r"""
  _ __   ___| |_ _ __ ___   __ _ _ __
 | '_ \ / _ \ __| '_ ` _ \ / _` | '_ \
 | | | |  __/ |_| | | | | | (_| | |_) |
 |_| |_|\___|\__|_| |_| |_|\__,_| .__/
                                  |_|
  Pure-Python Network Recon Tool  v1.0
  Inspired by nmap & masscan
  Author: G4MEOVER18  |  MIT License
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    # Ensure UTF-8 output on Windows terminals
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args   = parser.parse_args()

    if USE_COLOR:
        print(c(BANNER, CYAN + BOLD))
    else:
        print(BANNER)

    # Validate thread count
    args.threads = max(1, min(500, args.threads))

    # Select port list
    if args.top100:
        ports = TOP_100_PORTS
        print(c(f"[*] Scanning top {len(ports)} ports", CYAN))
    elif args.ports:
        ports = parse_ports(args.ports)
        print(c(f"[*] Scanning {len(ports)} port(s): {args.ports}", CYAN))
    else:
        ports = TOP_1000_PORTS
        print(c(f"[*] Scanning top {len(ports)} ports", CYAN))

    # Timing profile
    profile      = TIMING_PROFILES[args.timing]
    conn_timeout = args.timeout if args.timeout else profile["connect_timeout"]
    delay        = profile["delay"]
    threads      = max(1, int(args.threads * profile["thread_mult"]))
    print(c(f"[*] Timing T{args.timing} | timeout={conn_timeout}s | threads={threads}", CYAN))

    # Rate limiter
    rl = RateLimiter(args.rate) if args.rate > 0 else None

    # Scripts
    scripts: Optional[List[str]] = None
    if args.scripts:
        scripts = [s.strip() for s in args.scripts.split(",")]
        print(c(f"[*] Scripts enabled: {', '.join(scripts)}", CYAN))

    # UDP ports
    udp_ports: Optional[List[int]] = None
    if args.udp:
        udp_ports = parse_ports(args.udp)
        print(c(f"[*] UDP ports: {udp_ports}", CYAN))

    t_start      = time.monotonic()
    all_results: List[Tuple[str, List[PortResult], str]] = []

    for target in args.target:
        print(c(f"\n[>] Target: {target}", BOLD + WHITE))

        # Determine if subnet or single host
        is_subnet = "/" in target
        if is_subnet:
            subnet_results = scan_subnet(
                target, ports,
                threads=threads,
                connect_timeout=conn_timeout,
                banner_grab=not args.no_banner,
                scripts=scripts,
                udp_ports=udp_ports,
                rate_limiter=rl,
                timing_delay=delay,
                ping_first=not args.no_ping,
                host_threads=min(threads, 50),
            )
            all_results.extend(subnet_results)
        else:
            ip, port_results, os_guess = scan_host(
                target, ports,
                threads=threads,
                connect_timeout=conn_timeout,
                banner_grab=not args.no_banner,
                scripts=scripts,
                udp_ports=udp_ports,
                rate_limiter=rl,
                timing_delay=delay,
            )
            if port_results:
                all_results.append((ip, port_results, os_guess))
            _print_host_result(ip, port_results, os_guess)

        # Traceroute
        if args.traceroute:
            print(c("\n[*] Traceroute:", CYAN))
            hops = traceroute(target)
            for hop_n, hop_ip, rtt in hops:
                rtt_str = f"{rtt:.1f}ms" if rtt > 0 else "*"
                print(f"  {hop_n:>3}  {hop_ip:<20} {rtt_str}")

    elapsed = time.monotonic() - t_start

    # Summary
    total_open = sum(len(r) for _, r, _ in all_results)
    print()
    print(c(f"[=] Scan complete in {elapsed:.2f}s — {total_open} open port(s) across "
            f"{len(all_results)} host(s)", BOLD + GREEN))

    # Write output files
    if args.oN:
        content = format_normal(elapsed, " ".join(args.target), all_results)
        _write_file(args.oN, content)
        print(c(f"[+] Normal output written to {args.oN}", GREEN))

    if args.oJ:
        content = format_json(elapsed, " ".join(args.target), all_results)
        _write_file(args.oJ, content)
        print(c(f"[+] JSON output written to {args.oJ}", GREEN))

    if args.oG:
        content = format_grepable(elapsed, " ".join(args.target), all_results)
        _write_file(args.oG, content)
        print(c(f"[+] Grepable output written to {args.oG}", GREEN))


def _write_file(path: str, content: str):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except IOError as e:
        print(c(f"[!] Could not write {path}: {e}", RED), file=sys.stderr)


if __name__ == "__main__":
    main()
