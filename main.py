"""
PortRecon - network vulnerability scanner.

Pipeline: TCP connect scan -> banner grabbing -> NVD CVE lookup -> HTML/JSON report.

Usage:
    python main.py --target <IP or hostname> --ports <range> [--threads N] [--output NAME]

Example:
    python main.py --target 192.168.56.101 --ports 1-1000 --output metasploitable
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime

from scanner.banner_grabber import ServiceInfo, grab_banners
from scanner.cve_lookup import CVELookup, Vulnerability
from scanner.port_scanner import (
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    ProgressCallback,
    parse_port_range,
    resolve_target,
    scan_ports,
)
from scanner.report_generator import build_scan_data, generate_reports

BANNER = r"""
  ____            _   ____
 |  _ \ ___  _ __| |_|  _ \ ___  ___ ___  _ __
 | |_) / _ \| '__| __| |_) / _ \/ __/ _ \| '_ \
 |  __/ (_) | |  | |_|  _ <  __/ (_| (_) | | | |
 |_|   \___/|_|   \__|_| \_\___|\___\___/|_| |_|
        Network Vulnerability Scanner
"""

LEGAL_WARNING = """\
LEGAL WARNING
-------------
Port scanning and vulnerability probing of systems without permission may be
illegal in your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the
UK Computer Misuse Act) and may violate your ISP's or hosting provider's terms.

Only scan systems that you own or have EXPLICIT WRITTEN AUTHORISATION to test.
You are solely responsible for how you use this tool.
"""


# ------------------------------------------------------------------ output
class Color:
    """ANSI colour codes, disabled when output isn't a terminal or NO_COLOR is set."""

    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if enabled and os.name == "nt":
        os.system("")  # Enables ANSI escape processing in the Windows console.

    @classmethod
    def wrap(cls, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text


SEVERITY_COLORS: dict[str, str] = {"CRITICAL": "1;91", "HIGH": "91", "MEDIUM": "93", "LOW": "94"}


def info(msg: str) -> None:
    print(f"{Color.wrap('[*]', '96')} {msg}")


def good(msg: str) -> None:
    print(f"{Color.wrap('[+]', '92')} {msg}")


def warn(msg: str) -> None:
    print(f"{Color.wrap('[!]', '93')} {msg}")


def make_progress_printer(total: int) -> ProgressCallback:
    """Return a progress callback that redraws a single terminal line.

    Output is throttled to ~200 redraws per scan so large port ranges don't
    spend more time printing than scanning.
    """
    step = max(1, total // 200)

    def _progress(checked: int, total_: int) -> None:
        if checked % step and checked != total_:
            return
        pct = checked / total_ * 100
        sys.stdout.write(f"\r{Color.wrap('[*]', '96')} Scanning... {checked}/{total_} ports checked ({pct:5.1f}%)")
        sys.stdout.flush()
        if checked == total_:
            sys.stdout.write("\n")

    return _progress


# --------------------------------------------------------------------- CLI
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="portrecon",
        description="Multi-threaded TCP port scanner with banner grabbing and NVD CVE lookup.",
        epilog="Only scan systems you own or are explicitly authorised to test.",
    )
    parser.add_argument("--target", "-t", required=True, help="Target IPv4 address or hostname")
    parser.add_argument("--ports", "-p", default="1-1000",
                        help="Ports to scan, e.g. 1-1000, 22,80,443 or 1-100,8080 (default: 1-1000)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Concurrent scanning threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Per-port connect timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--output", "-o", help="Base name for report files (a timestamp is appended)")
    parser.add_argument("--max-cves", type=int, default=10,
                        help="Maximum CVEs to report per service (default: 10)")
    parser.add_argument("--no-cve", action="store_true", help="Skip the NVD vulnerability lookup")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug logging")
    args = parser.parse_args(argv)

    if not 1 <= args.threads <= 1000:
        parser.error("--threads must be between 1 and 1000")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        args.port_list = parse_port_range(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def confirm_authorisation(target: str) -> bool:
    """Show the legal warning and require the user to type 'yes'."""
    print(Color.wrap(LEGAL_WARNING, "93"))
    try:
        answer = input(f"Do you have authorisation to scan {Color.wrap(target, '1')}? Type 'yes' to continue: ")
    except EOFError:
        return False
    return answer.strip().lower() == "yes"


# ---------------------------------------------------------------- pipeline
def lookup_vulnerabilities(services: list[ServiceInfo], max_cves: int) -> dict[int, list[Vulnerability]]:
    """Query NVD for every service with an identified product and version."""
    client = CVELookup(max_results=max_cves)
    if not client.api_key:
        info("No NVD_API_KEY set - using public rate limit (5 requests / 30s)")

    results: dict[int, list[Vulnerability]] = {}
    for svc in services:
        if not (svc.product and svc.version):
            warn(f"Port {svc.port}: version unknown, skipping CVE lookup")
            continue
        info(f"Port {svc.port}: looking up CVEs for {svc.display_name}...")
        vulns = client.search(svc.product, svc.version)
        results[svc.port] = vulns
        if vulns:
            counts = ", ".join(
                Color.wrap(f"{sum(v.severity == sev for v in vulns)} {sev.lower()}", SEVERITY_COLORS[sev])
                for sev in SEVERITY_COLORS
                if any(v.severity == sev for v in vulns)
            )
            good(f"Port {svc.port}: {len(vulns)} CVE(s) found ({counts or 'unscored'})")
    return results


def print_summary(services: list[ServiceInfo], vulns: dict[int, list[Vulnerability]],
                  html_path: str, json_path: str, duration: float) -> None:
    """Print the end-of-scan summary table."""
    total_vulns = sum(len(v) for v in vulns.values())
    print()
    print(Color.wrap("=" * 64, "96"))
    print(Color.wrap(" SCAN SUMMARY", "1"))
    print(Color.wrap("=" * 64, "96"))
    if services:
        print(f" {'PORT':<10}{'SERVICE':<14}{'PRODUCT':<28}{'CVEs':>6}")
        for svc in services:
            count = len(vulns.get(svc.port, []))
            print(f" {str(svc.port) + '/tcp':<10}{svc.service:<14}{svc.display_name[:27]:<28}{count:>6}")
        print(Color.wrap("-" * 64, "96"))
    print(f" Open ports found:      {len(services)}")
    print(f" Vulnerabilities found: {total_vulns}")
    for sev, code in SEVERITY_COLORS.items():
        n = sum(v.severity == sev for vs in vulns.values() for v in vs)
        if n:
            print(f"   {Color.wrap(f'{sev:<9}', code)} {n}")
    print(f" Scan duration:         {duration:.1f}s")
    print(f" HTML report:           {html_path}")
    print(f" JSON report:           {json_path}")
    print(Color.wrap("=" * 64, "96"))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="    %(levelname)s: %(message)s")

    print(Color.wrap(BANNER, "96"))
    if not confirm_authorisation(args.target):
        warn("Authorisation not confirmed. Aborting.")
        return 1

    try:
        ip = resolve_target(args.target)
    except ValueError as exc:
        warn(str(exc))
        return 1

    started = datetime.now()
    t0 = time.perf_counter()
    info(f"Target: {args.target} ({ip})  |  Ports: {len(args.port_list)}  |  "
         f"Threads: {args.threads}  |  Timeout: {args.timeout}s")

    # 1. Port scan
    open_ports = scan_ports(ip, args.port_list, threads=args.threads, timeout=args.timeout,
                            progress_callback=make_progress_printer(len(args.port_list)))
    if open_ports:
        good(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        warn("No open ports found.")

    # 2. Banner grabbing
    services: list[ServiceInfo] = []
    if open_ports:
        info("Grabbing service banners...")
        services = grab_banners(ip, open_ports)
        for svc in services:
            good(f"{svc.port}/tcp  {svc.service:<12} {svc.display_name}")

    # 3. CVE lookup
    vulns: dict[int, list[Vulnerability]] = {}
    if services and not args.no_cve:
        info("Querying the NIST NVD for known vulnerabilities...")
        vulns = lookup_vulnerabilities(services, args.max_cves)

    # 4. Reports
    finished = datetime.now()
    data = build_scan_data(args.target, ip, args.ports, len(args.port_list),
                           started, finished, services, vulns)
    html_path, json_path = generate_reports(data, args.output)
    print_summary(services, vulns, str(html_path.resolve()), str(json_path.resolve()),
                  time.perf_counter() - t0)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        warn("Scan interrupted by user.")
        sys.exit(130)
