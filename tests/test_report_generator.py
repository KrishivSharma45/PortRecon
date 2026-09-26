"""Tests for scanner.report_generator."""

import json
from datetime import datetime, timedelta

from scanner.banner_grabber import ServiceInfo
from scanner.cve_lookup import Vulnerability
from scanner.report_generator import build_scan_data, generate_reports, render_html


def _vuln(cve_id, score, severity):
    return Vulnerability(cve_id, "desc", score, severity, "3.1", None, f"https://nvd.nist.gov/vuln/detail/{cve_id}")


def _sample_data(services=None, vulns=None):
    start = datetime(2026, 1, 1, 12, 0, 0)
    return build_scan_data(
        "example.test", "192.0.2.1", "1-1000", 1000, start, start + timedelta(seconds=5),
        services if services is not None else [ServiceInfo(22, "ssh", "OpenSSH", "7.4", "SSH-2.0-OpenSSH_7.4")],
        vulns if vulns is not None else {22: [_vuln("CVE-1", 9.8, "CRITICAL"), _vuln("CVE-2", 7.5, "HIGH")]},
    )


def test_build_scan_data_summary():
    data = _sample_data()
    assert data["duration_seconds"] == 5.0
    assert data["summary"]["open_ports"] == 1
    assert data["summary"]["vulnerabilities"] == 2
    assert data["summary"]["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert data["services"][0]["display_name"] == "OpenSSH 7.4"
    assert len(data["services"][0]["vulnerabilities"]) == 2


def test_build_scan_data_is_json_serialisable():
    json.dumps(_sample_data())


def test_render_html_contains_findings():
    html = render_html(_sample_data())
    assert "OpenSSH" in html
    assert "CVE-1" in html
    assert "sev-CRITICAL" in html


def test_render_html_escapes_untrusted_banner():
    evil = ServiceInfo(80, "http", "<script>alert(1)</script>", None, "Server: <img src=x onerror=alert(1)>")
    html = render_html(_sample_data(services=[evil], vulns={}))
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_render_html_with_no_findings():
    html = render_html(_sample_data(services=[], vulns={}))
    assert "No open ports found." in html
    assert "No known vulnerabilities" in html


def test_generate_reports_writes_both_files(tmp_path):
    html_path, json_path = generate_reports(_sample_data(), "my scan/../x", output_dir=tmp_path)
    assert html_path.parent == tmp_path and json_path.parent == tmp_path
    assert html_path.suffix == ".html" and json_path.suffix == ".json"
    assert "/" not in html_path.name and "\\" not in html_path.name
    assert json.loads(json_path.read_text(encoding="utf-8"))["ip"] == "192.0.2.1"
    assert html_path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_generate_reports_default_name(tmp_path):
    html_path, _ = generate_reports(_sample_data(), output_dir=tmp_path)
    assert html_path.name.startswith("portrecon_192.0.2.1_")
