"""
Service banner grabbing and fingerprinting.

For each open port this module:

1. Connects and waits briefly for a *passive* banner. Many protocols
   (SSH, FTP, SMTP, POP3, IMAP, MySQL) greet the client first.
2. If nothing arrives, sends a protocol-appropriate *probe* (an HTTP
   ``HEAD`` request for web ports, wrapped in TLS for HTTPS ports).
3. Matches the response against a set of regex signatures to extract a
   product name and version, e.g. ``OpenSSH 7.4`` or ``Apache httpd 2.4.29``.

Every network failure is caught: a port that never answers still yields a
:class:`ServiceInfo` with a best-guess service name from the port number.

Can be run on its own for quick testing::

    python -m scanner.banner_grabber 127.0.0.1 22,80
"""

from __future__ import annotations

import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any

DEFAULT_TIMEOUT: float = 3.0
RECV_BYTES: int = 2048

# Ports where the server speaks HTTP; TLS_PORTS additionally need a TLS handshake.
HTTP_PORTS: frozenset[int] = frozenset({80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888})
TLS_PORTS: frozenset[int] = frozenset({443, 4443, 8443, 9443})

# Fallback service names when a banner can't be identified.
COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}


@dataclass(frozen=True)
class Signature:
    """A regex that identifies a product in a banner.

    The pattern's first capture group, if present, is taken as the version.
    """

    service: str
    product: str
    pattern: re.Pattern[str]


def _sig(service: str, product: str, pattern: str) -> Signature:
    return Signature(service, product, re.compile(pattern, re.IGNORECASE))


# Ordered most-specific first; the first match wins.
SIGNATURES: list[Signature] = [
    # SSH
    _sig("ssh", "OpenSSH", r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)"),
    _sig("ssh", "Dropbear", r"SSH-[\d.]+-dropbear[_-]([\w.]+)"),
    # FTP
    _sig("ftp", "vsftpd", r"vsFTPd\s+([\d.]+)"),
    _sig("ftp", "ProFTPD", r"ProFTPD\s+([\d.]+\w*)"),
    _sig("ftp", "Pure-FTPd", r"Pure-FTPd(?:\s+([\d.]+))?"),
    _sig("ftp", "FileZilla Server", r"FileZilla Server(?:\s+(?:version\s+)?([\d.]+))?"),
    # Mail
    _sig("smtp", "Postfix", r"ESMTP Postfix"),
    _sig("smtp", "Exim", r"Exim\s+([\d.]+)"),
    _sig("smtp", "Sendmail", r"Sendmail\s+([\d.]+)"),
    _sig("pop3", "Dovecot", r"Dovecot"),
    # Web servers (from the HTTP "Server:" header)
    _sig("http", "Apache httpd", r"Server:\s*Apache(?:/([\d.]+))?"),
    _sig("http", "nginx", r"Server:\s*nginx(?:/([\d.]+))?"),
    _sig("http", "Microsoft IIS", r"Server:\s*Microsoft-IIS(?:/([\d.]+))?"),
    _sig("http", "lighttpd", r"Server:\s*lighttpd(?:/([\d.]+))?"),
    _sig("http", "Apache Tomcat", r"Server:\s*Apache-Coyote(?:/([\d.]+))?"),
    _sig("http", "Jetty", r"Server:\s*Jetty\(([\w.]+)\)"),
    _sig("http", "Werkzeug", r"Server:\s*Werkzeug(?:/([\d.]+))?"),
    _sig("http", "Python http.server", r"Server:\s*SimpleHTTP(?:/([\d.]+))?"),
    # Other
    _sig("redis", "Redis", r"redis_version:([\d.]+)"),
]

_SERVER_HEADER = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class ServiceInfo:
    """Fingerprint result for one open port."""

    port: int
    service: str = "unknown"
    product: str | None = None
    version: str | None = None
    banner: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """Human-readable product string, e.g. ``"OpenSSH 7.4"``."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product or self.service

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        data = asdict(self)
        data["display_name"] = self.display_name
        return data


def _clean(raw: bytes) -> str:
    """Decode raw bytes and strip non-printable characters (keeps newlines)."""
    text = raw.decode("utf-8", errors="replace")
    return "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t").strip()


def _parse_mysql_greeting(raw: bytes) -> str | None:
    """
    Extract the server version from a MySQL/MariaDB handshake packet.

    The packet is: 3-byte length, 1-byte sequence id, protocol version
    (0x0a), then the null-terminated server version string.
    """
    if len(raw) > 5 and raw[4] == 0x0A:
        end = raw.find(b"\x00", 5)
        if end > 5:
            return raw[5:end].decode("ascii", errors="replace")
    return None


def _http_probe(host: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: PortRecon\r\n\r\n".encode()


def _recv(sock: socket.socket) -> bytes:
    """Receive up to RECV_BYTES, returning b'' on timeout or error."""
    try:
        return sock.recv(RECV_BYTES)
    except (socket.timeout, OSError):
        return b""


def grab_banner(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """
    Retrieve the raw banner/response from a service.

    Args:
        ip: Target IPv4 address.
        port: Open TCP port.
        timeout: Socket timeout in seconds for connect and each read.

    Returns:
        Raw response bytes, or ``b''`` if the service didn't respond.
    """
    try:
        if port in TLS_PORTS:
            # We're fingerprinting, not trusting: accept any certificate.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as sock:
                    sock.sendall(_http_probe(ip))
                    return _recv(sock)

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port in HTTP_PORTS:
                sock.sendall(_http_probe(ip))
                return _recv(sock)

            # Give "server speaks first" protocols a moment to greet us.
            sock.settimeout(min(timeout, 2.0))
            data = _recv(sock)
            if data:
                return data

            # Silent service: try HTTP, the most common protocol on odd ports.
            sock.settimeout(timeout)
            sock.sendall(_http_probe(ip))
            return _recv(sock)
    except (OSError, ssl.SSLError):
        return b""


def identify_service(port: int, raw: bytes) -> ServiceInfo:
    """
    Fingerprint a service from its port number and raw banner.

    Args:
        port: TCP port the banner came from.
        raw: Raw bytes returned by :func:`grab_banner`.

    Returns:
        A populated :class:`ServiceInfo`.
    """
    info = ServiceInfo(port=port, service=COMMON_SERVICES.get(port, "unknown"))
    info.banner = _clean(raw)

    mysql_version = _parse_mysql_greeting(raw)
    if mysql_version:
        info.service = "mysql"
        info.product = "MariaDB" if "mariadb" in mysql_version.lower() else "MySQL"
        version_match = re.match(r"[\d.]+", mysql_version)
        info.version = version_match.group(0) if version_match else None
        info.banner = f"MySQL handshake: {mysql_version}"
        return info

    if not info.banner:
        return info

    for sig in SIGNATURES:
        match = sig.pattern.search(info.banner)
        if match:
            info.service = sig.service if port not in TLS_PORTS else "https"
            info.product = sig.product
            if match.groups() and match.group(1):
                info.version = match.group(1).rstrip(".")
            break
    else:
        # No signature matched: fall back to generic protocol detection.
        if info.banner.startswith("HTTP/"):
            info.service = "https" if port in TLS_PORTS else "http"
            server = _SERVER_HEADER.search(info.banner)
            if server:
                info.product = server.group(1).strip()
        elif info.banner.startswith("SSH-"):
            info.service = "ssh"
            info.product = info.banner.splitlines()[0]

    return info


def fingerprint_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ServiceInfo:
    """Grab and identify the banner on a single port."""
    return identify_service(port, grab_banner(ip, port, timeout))


def grab_banners(
    ip: str,
    ports: list[int],
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = 20,
) -> list[ServiceInfo]:
    """
    Fingerprint several open ports concurrently.

    Args:
        ip: Target IPv4 address.
        ports: Open ports (typically from :func:`scanner.port_scanner.scan_ports`).
        timeout: Per-connection timeout in seconds.
        threads: Maximum concurrent connections.

    Returns:
        List of :class:`ServiceInfo`, in the same order as ``ports``.
    """
    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(ports)))) as executor:
        return list(executor.map(lambda p: fingerprint_port(ip, p, timeout), ports))


if __name__ == "__main__":
    from scanner.port_scanner import parse_port_range, resolve_target

    if len(sys.argv) != 3:
        print("Usage: python -m scanner.banner_grabber <target> <ports>")
        sys.exit(1)
    target_ip = resolve_target(sys.argv[1])
    for svc in grab_banners(target_ip, parse_port_range(sys.argv[2])):
        first_line = svc.banner.splitlines()[0] if svc.banner else "(no banner)"
        print(f"{svc.port:>5}/tcp  {svc.service:<12} {svc.display_name:<28} {first_line}")
