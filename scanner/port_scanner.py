"""
Multi-threaded TCP connect port scanner.

A TCP connect scan completes the full three-way handshake with each port using
the operating system's ``connect()`` call. It needs no raw-socket privileges,
which makes it portable and safe to run as a normal user, at the cost of being
noisier (connections are logged by the target) than a SYN scan.

Can be run on its own for quick testing::

    python -m scanner.port_scanner 127.0.0.1 1-1024
"""

from __future__ import annotations

import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

DEFAULT_TIMEOUT: float = 1.0
DEFAULT_THREADS: int = 100
MAX_PORT: int = 65535

ProgressCallback = Callable[[int, int], None]
"""Signature for progress callbacks: ``callback(checked, total)``."""


def parse_port_range(spec: str) -> list[int]:
    """
    Parse a port specification into a sorted list of unique ports.

    Supports single ports, ranges and comma-separated combinations::

        "80"            -> [80]
        "1-1000"        -> [1, 2, ..., 1000]
        "22,80,443"     -> [22, 80, 443]
        "1-100,443,8080-8090"

    Args:
        spec: The port specification string.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If the spec is malformed or contains out-of-range ports.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, _, end_str = part.partition("-")
            try:
                start, end = int(start_str), int(end_str)
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'") from None
            if start > end:
                raise ValueError(f"Range start is greater than end: '{part}'")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid port: '{part}'") from None

    if not ports:
        raise ValueError("No ports specified")
    if min(ports) < 1 or max(ports) > MAX_PORT:
        raise ValueError(f"Ports must be between 1 and {MAX_PORT}")
    return sorted(ports)


def resolve_target(target: str) -> str:
    """
    Resolve a hostname or IP address string to an IPv4 address.

    Args:
        target: Hostname (e.g. ``scanme.nmap.org``) or IPv4 address.

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        ValueError: If the target cannot be resolved.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from None


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Check whether a single TCP port is open using a connect scan.

    Args:
        ip: Target IPv4 address.
        port: TCP port to probe.
        timeout: Seconds to wait for the connection before giving up.

    Returns:
        ``True`` if the handshake completed (port open), ``False`` otherwise
        (closed, filtered, or any socket error).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            # connect_ex returns 0 on success instead of raising.
            return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan_ports(
    ip: str,
    ports: Iterable[int],
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    progress_callback: ProgressCallback | None = None,
) -> list[int]:
    """
    Scan many TCP ports concurrently and return the open ones.

    Args:
        ip: Target IPv4 address (use :func:`resolve_target` for hostnames).
        ports: Ports to scan.
        threads: Maximum number of worker threads.
        timeout: Per-port connection timeout in seconds.
        progress_callback: Optional ``callback(checked, total)`` invoked after
            every port completes. Useful for live progress output.

    Returns:
        Sorted list of open ports.
    """
    port_list = list(ports)
    total = len(port_list)
    open_ports: list[int] = []
    checked = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            port = futures[future]
            with lock:
                checked += 1
                if future.result():
                    open_ports.append(port)
                if progress_callback:
                    progress_callback(checked, total)

    return sorted(open_ports)


def _print_progress(checked: int, total: int) -> None:
    """Default single-line terminal progress indicator."""
    sys.stdout.write(f"\rScanning... {checked}/{total} ports checked")
    sys.stdout.flush()
    if checked == total:
        sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m scanner.port_scanner <target> <ports>")
        sys.exit(1)
    target_ip = resolve_target(sys.argv[1])
    found = scan_ports(target_ip, parse_port_range(sys.argv[2]), progress_callback=_print_progress)
    print(f"Open ports on {target_ip}: {found or 'none'}")
