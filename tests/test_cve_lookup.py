"""Tests for scanner.cve_lookup. No test here touches the real NVD API."""

import time

import pytest

from scanner import cve_lookup
from scanner.cve_lookup import CVELookup, RateLimiter, severity_from_score


def _nvd_item(cve_id, score, severity=None, metric="cvssMetricV31", text="Test description"):
    data = {"baseScore": score}
    entry = {"type": "Primary", "cvssData": data}
    if metric == "cvssMetricV2":
        entry["baseSeverity"] = severity
    else:
        data["baseSeverity"] = severity
    return {
        "cve": {
            "id": cve_id,
            "published": "2020-01-01T00:00:00",
            "descriptions": [{"lang": "es", "value": "Descripcion"}, {"lang": "en", "value": text}],
            "metrics": {metric: [entry]},
        }
    }


@pytest.mark.parametrize(
    ("score", "label"),
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"), (6.9, "MEDIUM"),
     (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "NONE"), (None, "UNKNOWN")],
)
def test_severity_from_score(score, label):
    assert severity_from_score(score) == label


def test_parse_cve_v31():
    vuln = CVELookup._parse_cve(_nvd_item("CVE-2011-2523", 9.8, "CRITICAL", text="backdoor"))
    assert vuln.cve_id == "CVE-2011-2523"
    assert vuln.cvss_score == 9.8
    assert vuln.severity == "CRITICAL"
    assert vuln.cvss_version == "3.1"
    assert vuln.description == "backdoor"
    assert vuln.url == "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"


def test_parse_cve_v2_derives_severity_from_score():
    # CVSS v2 labels 10.0 as HIGH, but we normalise to the v3 scale.
    vuln = CVELookup._parse_cve(_nvd_item("CVE-2000-0001", 10.0, "HIGH", metric="cvssMetricV2"))
    assert vuln.cvss_version == "2.0"
    assert vuln.severity == "CRITICAL"


def test_parse_cve_without_metrics():
    vuln = CVELookup._parse_cve({"cve": {"id": "CVE-2099-0001", "descriptions": []}})
    assert vuln.cvss_score is None
    assert vuln.severity == "UNKNOWN"
    assert vuln.description == "No description available."


@pytest.fixture
def fake_api(monkeypatch):
    """Replace the HTTP call with a stub and record the keywords requested."""
    calls = []
    response = {
        "vulnerabilities": [
            _nvd_item("CVE-LOW", 3.1, "LOW"),
            _nvd_item("CVE-CRIT", 9.8, "CRITICAL"),
            _nvd_item("CVE-MED", 5.0, "MEDIUM"),
        ]
    }

    def fake_request(self, keyword):
        calls.append(keyword)
        return response

    monkeypatch.setattr(CVELookup, "_request", fake_request)
    return calls


def test_search_sorts_by_score_and_limits(fake_api):
    results = CVELookup(api_key="", cache_path=None, max_results=2).search("OpenSSH", "7.4")
    assert [v.cve_id for v in results] == ["CVE-CRIT", "CVE-MED"]
    assert fake_api == ["OpenSSH 7.4"]


def test_search_applies_keyword_alias(fake_api):
    CVELookup(api_key="", cache_path=None).search("Apache httpd", "2.4.29")
    assert fake_api == ["Apache HTTP Server 2.4.29"]


def test_search_uses_memory_cache(fake_api):
    client = CVELookup(api_key="", cache_path=None)
    client.search("OpenSSH", "7.4")
    client.search("openssh", "7.4")
    assert len(fake_api) == 1


def test_search_uses_disk_cache(fake_api, tmp_path):
    cache_file = tmp_path / "cache.json"
    CVELookup(api_key="", cache_path=cache_file).search("OpenSSH", "7.4")
    assert cache_file.exists()
    results = CVELookup(api_key="", cache_path=cache_file).search("OpenSSH", "7.4")
    assert len(fake_api) == 1
    assert results[0].cve_id == "CVE-CRIT"


def test_expired_cache_entry_is_refetched(fake_api, monkeypatch):
    client = CVELookup(api_key="", cache_path=None)
    client.search("OpenSSH", "7.4")
    monkeypatch.setattr(cve_lookup, "CACHE_TTL_SECONDS", -1)
    client.search("OpenSSH", "7.4")
    assert len(fake_api) == 2


def test_api_failure_returns_empty_and_is_not_cached(monkeypatch):
    calls = []

    def failing_request(self, keyword):
        calls.append(keyword)
        return None

    monkeypatch.setattr(CVELookup, "_request", failing_request)
    client = CVELookup(api_key="", cache_path=None)
    assert client.search("OpenSSH", "7.4") == []
    assert client.search("OpenSSH", "7.4") == []
    assert len(calls) == 2


def test_empty_product_skips_request(fake_api):
    assert CVELookup(api_key="", cache_path=None).search("", None) == []
    assert fake_api == []


def test_corrupt_cache_file_is_ignored(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("{not json", encoding="utf-8")
    assert CVELookup(api_key="", cache_path=cache_file)._cache == {}


def test_api_key_raises_rate_limit():
    assert CVELookup(api_key="", cache_path=None).rate_limiter.max_calls == 5
    assert CVELookup(api_key="key", cache_path=None).rate_limiter.max_calls > 5


def test_rate_limiter_blocks_when_window_is_full():
    limiter = RateLimiter(max_calls=3, period=0.5)
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    assert time.monotonic() - start < 0.2
    limiter.wait()
    assert time.monotonic() - start >= 0.45
