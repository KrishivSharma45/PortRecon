"""Tests for scanner.banner_grabber."""

import socket
import threading

import pytest

from scanner.banner_grabber import fingerprint_port, grab_banners, identify_service


@pytest.mark.parametrize(
    ("port", "raw", "service", "product", "version"),
    [
        (22, b"SSH-2.0-OpenSSH_7.4\r\n", "ssh", "OpenSSH", "7.4"),
        (22, b"SSH-2.0-dropbear_2019.78\r\n", "ssh", "Dropbear", "2019.78"),
        (21, b"220 (vsFTPd 2.3.4)\r\n", "ftp", "vsftpd", "2.3.4"),
        (21, b"220 ProFTPD 1.3.5 Server\r\n", "ftp", "ProFTPD", "1.3.5"),
        (25, b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "smtp", "Postfix", None),
        (25, b"220 mx ESMTP Exim 4.92 Mon\r\n", "smtp", "Exim", "4.92"),
        (80, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n\r\n", "http", "Apache httpd", "2.4.29"),
        (80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "http", "nginx", "1.18.0"),
        (80, b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n", "http", "Microsoft IIS", "10.0"),
        (443, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n", "https", "nginx", "1.18.0"),
    ],
)
def test_identify_known_services(port, raw, service, product, version):
    info = identify_service(port, raw)
    assert (info.service, info.product, info.version) == (service, product, version)


def test_identify_mysql_handshake():
    packet = b"\x4a\x00\x00\x00\x0a5.7.33-0ubuntu0.18.04.1\x00rest-of-packet"
    info = identify_service(3306, packet)
    assert (info.service, info.product, info.version) == ("mysql", "MySQL", "5.7.33")


def test_identify_mariadb_handshake():
    packet = b"\x4a\x00\x00\x00\x0a5.5.5-10.3.34-MariaDB\x00rest"
    assert identify_service(3306, packet).product == "MariaDB"


def test_unknown_http_server_uses_server_header():
    info = identify_service(8000, b"HTTP/1.0 200 OK\r\nServer: CustomThing/9\r\n\r\n")
    assert info.service == "http"
    assert info.product == "CustomThing/9"
    assert info.version is None


def test_empty_banner_falls_back_to_port_name():
    info = identify_service(22, b"")
    assert info.service == "ssh"
    assert info.product is None
    assert info.display_name == "ssh"


def test_unknown_port_no_banner():
    info = identify_service(12345, b"")
    assert info.service == "unknown"
    assert info.banner == ""


def test_banner_strips_non_printable_characters():
    info = identify_service(21, b"220 hello\x00\x01\x02 world\r\n")
    assert "\x00" not in info.banner
    assert info.banner == "220 hello world"


def test_display_name():
    info = identify_service(22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
    assert info.display_name == "OpenSSH 8.9p1"
    assert info.to_dict()["display_name"] == "OpenSSH 8.9p1"


def _serve_once(payload: bytes) -> int:
    """Start a one-shot TCP server that sends ``payload`` on connect."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def handle():
        conn, _ = server.accept()
        with conn:
            conn.sendall(payload)
        server.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_fingerprint_live_socket():
    port = _serve_once(b"SSH-2.0-OpenSSH_7.4\r\n")
    info = fingerprint_port("127.0.0.1", port, timeout=2.0)
    assert info.product == "OpenSSH"
    assert info.version == "7.4"


def test_grab_banners_handles_closed_port_gracefully():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    [info] = grab_banners("127.0.0.1", [closed], timeout=1.0)
    assert info.banner == ""


def test_grab_banners_empty():
    assert grab_banners("127.0.0.1", []) == []
