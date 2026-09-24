"""
HTML and JSON report generation.

Turns scan findings into two artefacts saved under ``reports/``:

* ``<name>_<timestamp>.json`` - raw structured data, suitable for piping into
  other tools.
* ``<name>_<timestamp>.html`` - a self-contained, human-readable report with
  target info, an open-ports table and severity-colour-coded vulnerabilities.

Security note: banners and CVE descriptions come from untrusted sources (the
scanned host and a remote API), so every value is HTML-escaped before it is
written into the report to prevent script injection when the report is opened.

Can be run on its own to render a demo report::

    python -m scanner.report_generator
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from scanner.banner_grabber import ServiceInfo
from scanner.cve_lookup import SEVERITY_ORDER, Vulnerability

DEFAULT_REPORT_DIR = Path("reports")
SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def build_scan_data(
    target: str,
    ip: str,
    port_spec: str,
    ports_scanned: int,
    started: datetime,
    finished: datetime,
    services: list[ServiceInfo],
    vulnerabilities: dict[int, list[Vulnerability]],
) -> dict[str, Any]:
    """
    Assemble all findings into a single JSON-serialisable dict.

    Args:
        target: Target as given by the user (hostname or IP).
        ip: Resolved IPv4 address.
        port_spec: Port specification string that was scanned (e.g. ``"1-1000"``).
        ports_scanned: Number of ports checked.
        started: Scan start time.
        finished: Scan end time.
        services: Fingerprinted open ports.
        vulnerabilities: CVEs keyed by port number.

    Returns:
        The structured scan result used by both report formats.
    """
    service_entries = []
    for svc in services:
        entry = svc.to_dict()
        entry["vulnerabilities"] = [v.to_dict() for v in vulnerabilities.get(svc.port, [])]
        service_entries.append(entry)

    severity_counts = {sev: 0 for sev in SEVERITIES}
    for vulns in vulnerabilities.values():
        for v in vulns:
            if v.severity in severity_counts:
                severity_counts[v.severity] += 1

    return {
        "tool": "PortRecon",
        "target": target,
        "ip": ip,
        "port_spec": port_spec,
        "ports_scanned": ports_scanned,
        "scan_started": started.isoformat(timespec="seconds"),
        "scan_finished": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 2),
        "summary": {
            "open_ports": len(services),
            "vulnerabilities": sum(len(v) for v in vulnerabilities.values()),
            "by_severity": severity_counts,
        },
        "services": service_entries,
    }


# --------------------------------------------------------------------- HTML
_CSS = """
:root {
  --bg: #f5f7fa; --panel: #ffffff; --text: #1f2933; --muted: #616e7c; --border: #e4e7eb;
  --accent: #2563eb; --code-bg: #f0f2f5;
  --critical: #b91c1c; --high: #ea580c; --medium: #ca8a04; --low: #2563eb; --unknown: #6b7280;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f141a; --panel: #18202a; --text: #e4e7eb; --muted: #9aa5b1; --border: #2a3441;
    --accent: #60a5fa; --code-bg: #111820;
    --critical: #f87171; --high: #fb923c; --medium: #facc15; --low: #60a5fa; --unknown: #9ca3af;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 1080px; margin: 0 auto; padding: 32px 16px 48px; }
header h1 { margin: 0; font-size: 26px; letter-spacing: -0.02em; }
header p { margin: 4px 0 0; color: var(--muted); }
h2 { font-size: 18px; margin: 36px 0 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 24px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.card .label { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.card .value { font-size: 17px; font-weight: 600; margin-top: 2px; overflow-wrap: break-word; }
.sev-counts { display: flex; flex-wrap: wrap; gap: 10px; }
.sev-counts .card { flex: 1 1 120px; border-top: 4px solid var(--sev); }
.sev-counts .value { color: var(--sev); font-size: 26px; }
.table-wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
tr:last-child td { border-bottom: none; }
code, pre { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: 13px; }
pre { margin: 0; white-space: pre-wrap; word-break: break-all; background: var(--code-bg);
  padding: 6px 8px; border-radius: 6px; max-height: 7.5em; overflow: auto; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 700;
  color: #fff; background: var(--sev); letter-spacing: .03em; }
.sev-CRITICAL { --sev: var(--critical); } .sev-HIGH { --sev: var(--high); }
.sev-MEDIUM { --sev: var(--medium); } .sev-LOW { --sev: var(--low); }
.sev-UNKNOWN, .sev-NONE { --sev: var(--unknown); }
.service-block { margin-bottom: 22px; }
.service-block h3 { font-size: 15px; margin: 0 0 8px; }
.service-block h3 span { color: var(--muted); font-weight: 400; }
.vuln { background: var(--panel); border: 1px solid var(--border); border-left: 5px solid var(--sev);
  border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
.vuln-head { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.vuln-head a { font-weight: 600; color: var(--accent); text-decoration: none; }
.vuln-head a:hover { text-decoration: underline; }
.vuln-head .score { color: var(--muted); font-size: 13px; }
.vuln p { margin: 6px 0 0; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 40px; font-size: 13px; color: var(--muted); border-top: 1px solid var(--border); padding-top: 16px; }
"""


def _sev_class(severity: str) -> str:
    return f"sev-{severity if severity in SEVERITY_ORDER else 'UNKNOWN'}"


def _render_ports_table(services: list[dict[str, Any]]) -> str:
    if not services:
        return '<p class="empty">No open ports found.</p>'
    rows = []
    for svc in services:
        worst = max((v["severity"] for v in svc["vulnerabilities"]),
                    key=lambda s: SEVERITY_ORDER.get(s, -1), default=None)
        vuln_cell = (f'<span class="badge {_sev_class(worst)}">{len(svc["vulnerabilities"])}</span>'
                     if worst else "0")
        banner = escape(svc["banner"]) if svc["banner"] else '<span class="empty">no banner</span>'
        rows.append(
            "<tr>"
            f"<td><code>{svc['port']}/tcp</code></td>"
            f"<td>{escape(svc['service'])}</td>"
            f"<td>{escape(svc['product'] or '-')}</td>"
            f"<td>{escape(svc['version'] or '-')}</td>"
            f"<td>{vuln_cell}</td>"
            f"<td><pre>{banner}</pre></td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Product</th>'
        "<th>Version</th><th>CVEs</th><th>Banner</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _render_vulnerabilities(services: list[dict[str, Any]]) -> str:
    blocks = []
    for svc in services:
        if not svc["vulnerabilities"]:
            continue
        items = []
        for v in svc["vulnerabilities"]:
            score = f"CVSS {v['cvss_version']}: {v['cvss_score']:.1f}" if v["cvss_score"] is not None else "No CVSS score"
            items.append(
                f'<div class="vuln {_sev_class(v["severity"])}"><div class="vuln-head">'
                f'<span class="badge">{escape(v["severity"])}</span>'
                f'<a href="{escape(v["url"])}" target="_blank" rel="noopener noreferrer">{escape(v["cve_id"])}</a>'
                f'<span class="score">{escape(score)}</span></div>'
                f"<p>{escape(v['description'])}</p></div>"
            )
        blocks.append(
            f'<div class="service-block"><h3>{escape(svc["display_name"])} '
            f"<span>&middot; port {svc['port']}/tcp</span></h3>{''.join(items)}</div>"
        )
    return "".join(blocks) or '<p class="empty">No known vulnerabilities matched the identified services.</p>'


def render_html(data: dict[str, Any]) -> str:
    """
    Render scan data (from :func:`build_scan_data`) as a standalone HTML page.

    Args:
        data: Structured scan result.

    Returns:
        Complete HTML document as a string.
    """
    summary = data["summary"]
    target_label = data["target"] if data["target"] == data["ip"] else f"{data['target']} ({data['ip']})"
    info_cards = [
        ("Target", target_label),
        ("Scan started", data["scan_started"].replace("T", " ")),
        ("Duration", f"{data['duration_seconds']}s"),
        ("Ports scanned", f"{data['ports_scanned']} ({data['port_spec']})"),
        ("Open ports", str(summary["open_ports"])),
        ("Vulnerabilities", str(summary["vulnerabilities"])),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="label">{escape(label)}</div><div class="value">{escape(value)}</div></div>'
        for label, value in info_cards
    )
    sev_html = "".join(
        f'<div class="card sev-{sev}"><div class="label">{sev.title()}</div>'
        f'<div class="value">{summary["by_severity"][sev]}</div></div>'
        for sev in SEVERITIES
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PortRecon Report - {escape(data['target'])}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
  <header>
    <h1>PortRecon Scan Report</h1>
    <p>Network vulnerability assessment for <strong>{escape(target_label)}</strong></p>
  </header>
  <section class="grid">{cards_html}</section>

  <h2>Severity overview</h2>
  <section class="sev-counts">{sev_html}</section>

  <h2>Open ports &amp; services</h2>
  {_render_ports_table(data["services"])}

  <h2>Vulnerabilities</h2>
  {_render_vulnerabilities(data["services"])}

  <footer>
    Generated by PortRecon on {escape(data['scan_finished'].replace('T', ' '))}.
    CVEs are matched by keyword search against the NIST NVD and may include false positives;
    verify each finding before acting on it. Only scan systems you are authorised to test.
  </footer>
</main>
</body>
</html>
"""


# ------------------------------------------------------------------- output
def _safe_name(name: str) -> str:
    """Make a string safe for use in a filename."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "scan"


def generate_reports(
    data: dict[str, Any],
    output_name: str | None = None,
    output_dir: Path = DEFAULT_REPORT_DIR,
) -> tuple[Path, Path]:
    """
    Write the HTML and JSON reports to disk.

    Args:
        data: Structured scan result from :func:`build_scan_data`.
        output_name: Base filename (without extension). Defaults to
            ``portrecon_<ip>``. A timestamp is always appended.
        output_dir: Directory to write into (created if missing).

    Returns:
        ``(html_path, json_path)``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    base = _safe_name(output_name or f"portrecon_{data['ip']}")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = output_dir / f"{base}_{stamp}.html"
    json_path = output_dir / f"{base}_{stamp}.json"

    html_path.write_text(render_html(data), encoding="utf-8")
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return html_path, json_path


if __name__ == "__main__":
    # Render a demo report from sample data so the layout can be previewed
    # without scanning anything.
    now = datetime.now()
    demo_services = [
        ServiceInfo(21, "ftp", "vsftpd", "2.3.4", "220 (vsFTPd 2.3.4)"),
        ServiceInfo(22, "ssh", "OpenSSH", "7.4", "SSH-2.0-OpenSSH_7.4"),
        ServiceInfo(80, "http", "Apache httpd", "2.4.29", "HTTP/1.1 200 OK\nServer: Apache/2.4.29 (Ubuntu)"),
    ]
    demo_vulns = {
        21: [Vulnerability("CVE-2011-2523", "vsftpd 2.3.4 contains a backdoor which opens a shell on port 6200/tcp.",
                           9.8, "CRITICAL", "3.1", "2019-11-27", "https://nvd.nist.gov/vuln/detail/CVE-2011-2523")],
        22: [Vulnerability("CVE-2016-10012", "Shared memory manager bounds check issue in sshd in OpenSSH before 7.4.",
                           7.8, "HIGH", "3.1", "2017-01-05", "https://nvd.nist.gov/vuln/detail/CVE-2016-10012")],
    }
    demo = build_scan_data("demo.local", "192.0.2.10", "1-1000", 1000, now, now, demo_services, demo_vulns)
    html_out, json_out = generate_reports(demo, "demo")
    print(f"HTML report: {html_out}\nJSON report: {json_out}")
