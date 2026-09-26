"""Tests for scanner.port_scanner."""

import socket

import pytest

from scanner.port_scanner import parse_port_range, resolve_target, scan_port, scan_ports


@pytest.fixture
def listening_port():
    """Open a local TCP listener and yield its port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        yield server.getsockname()[1]


@pytest.fixture
def closed_port():
    """Return a local port that is (almost certainly) not listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", [80]),
        ("22,80,443", [22, 80, 443]),
        ("1-5", [1, 2, 3, 4, 5]),
        ("1-3,2,5", [1, 2, 3, 5]),
        (" 443 , 80 ", [80, 443]),
    ],
)
def test_parse_port_range_valid(spec, expected):
    assert parse_port_range(spec) == expected


def test_parse_port_range_full_range():
    assert len(parse_port_range("1-65535")) == 65535


@pytest.mark.parametrize("spec", ["", "abc", "10-1", "0-5", "70000", "1-2-3", "80,x"])
def test_parse_port_range_invalid(spec):
    with pytest.raises(ValueError):
        parse_port_range(spec)


def test_resolve_target_ip_passthrough():
    assert resolve_target("127.0.0.1") == "127.0.0.1"


def test_resolve_target_invalid():
    with pytest.raises(ValueError):
        resolve_target("no-such-host.invalid")


def test_scan_port_open(listening_port):
    assert scan_port("127.0.0.1", listening_port, timeout=1.0)


def test_scan_port_closed(closed_port):
    assert not scan_port("127.0.0.1", closed_port, timeout=1.0)


def test_scan_ports_finds_only_open_and_reports_progress(listening_port, closed_port):
    progress = []
    result = scan_ports(
        "127.0.0.1",
        [closed_port, listening_port],
        threads=4,
        timeout=1.0,
        progress_callback=lambda checked, total: progress.append((checked, total)),
    )
    assert result == [listening_port]
    assert progress[-1] == (2, 2)
    assert [c for c, _ in progress] == [1, 2]
