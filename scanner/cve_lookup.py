"""
CVE lookup against the NIST National Vulnerability Database (NVD) API 2.0.

Given a product and version (e.g. ``OpenSSH`` / ``7.4``) this module runs a
keyword search against ``https://services.nvd.nist.gov/rest/json/cves/2.0``
and returns the matching CVEs with their CVSS score and severity.

Features:

* **Rate limiting** - a thread-safe sliding-window limiter keeps us within NVD's
  public limits (5 requests / 30 s without an API key, 50 / 30 s with one).
  Set the ``NVD_API_KEY`` environment variable to use a key.
* **Caching** - results are cached in memory and on disk
  (``.cache/nvd_cache.json``, 24 h TTL) so repeated lookups never hit the API.
* **Graceful failure** - network errors, HTTP errors and malformed responses
  are logged and yield an empty result instead of crashing the scan.

Keyword matching is heuristic: it finds CVEs whose description mentions the
product and version, which may include false positives. Always verify findings.

Can be run on its own for quick testing::

    python -m scanner.cve_lookup OpenSSH 7.4
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_PATH = Path(".cache") / "nvd_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RESULTS_PER_PAGE = 200

logger = logging.getLogger(__name__)

# Banner product names that NVD descriptions phrase differently.
KEYWORD_ALIASES: dict[str, str] = {
    "Apache httpd": "Apache HTTP Server",
    "Python http.server": "Python",
}

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}


@dataclass
class Vulnerability:
    """A single CVE matched against a service."""

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    cvss_version: str | None
    published: str | None
    url: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return asdict(self)


def severity_from_score(score: float | None) -> str:
    """
    Map a CVSS base score to its qualitative severity rating (CVSS v3 scale).

    Args:
        score: CVSS base score from 0.0 to 10.0, or ``None``.

    Returns:
        One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``NONE`` or ``UNKNOWN``.
    """
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Allows at most ``max_calls`` calls in any ``period``-second window;
    :meth:`wait` blocks until a call is permitted.
    """

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block until another call is allowed, then record it."""
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                sleep_for = self.period - (now - self._calls[0])
            logger.info("NVD rate limit reached, waiting %.1fs", sleep_for)
            time.sleep(sleep_for)


class CVELookup:
    """Client for NVD keyword searches with rate limiting and caching.

    Args:
        api_key: Optional NVD API key. Defaults to ``$NVD_API_KEY``.
        cache_path: JSON file for the persistent cache, or ``None`` to keep
            the cache in memory only.
        max_results: Maximum CVEs returned per lookup (highest scores first).
    """

    def __init__(
        self,
        api_key: str | None = None,
        cache_path: Path | None = DEFAULT_CACHE_PATH,
        max_results: int = 10,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
        self.cache_path = cache_path
        self.max_results = max_results
        # Stay slightly under the documented limits to allow for clock skew.
        self.rate_limiter = RateLimiter(max_calls=45 if self.api_key else 5, period=30.0)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "PortRecon/1.0"
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        self._cache: dict[str, dict[str, Any]] = self._load_cache()
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------ cache
    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Ignoring unreadable CVE cache %s: %s", self.cache_path, exc)
            return {}

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache), encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not write CVE cache %s: %s", self.cache_path, exc)

    def _cache_get(self, key: str) -> list[dict[str, Any]] | None:
        with self._cache_lock:
            entry = self._cache.get(key)
        if entry and time.time() - entry.get("timestamp", 0) < CACHE_TTL_SECONDS:
            return entry["results"]
        return None

    def _cache_put(self, key: str, results: list[dict[str, Any]]) -> None:
        with self._cache_lock:
            self._cache[key] = {"timestamp": time.time(), "results": results}
            self._save_cache()

    # -------------------------------------------------------------------- API
    def _request(self, keyword: str) -> dict[str, Any] | None:
        """Call the NVD API with retries. Returns parsed JSON or ``None``."""
        params = {"keywordSearch": keyword, "resultsPerPage": RESULTS_PER_PAGE}
        for attempt in range(1, MAX_RETRIES + 1):
            self.rate_limiter.wait()
            try:
                resp = self.session.get(NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as exc:
                logger.warning("NVD request failed (attempt %d/%d): %s", attempt, MAX_RETRIES, exc)
            else:
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        logger.warning("NVD returned invalid JSON for '%s'", keyword)
                        return None
                # 403/429 = throttled, 5xx = NVD having a bad day; both are retryable.
                if resp.status_code not in (403, 429, 500, 502, 503, 504):
                    logger.warning("NVD returned HTTP %d for '%s'", resp.status_code, keyword)
                    return None
                logger.warning("NVD returned HTTP %d (attempt %d/%d)", resp.status_code, attempt, MAX_RETRIES)
            time.sleep(2 ** attempt)
        return None

    @staticmethod
    def _parse_cve(item: dict[str, Any]) -> Vulnerability:
        """Convert one NVD ``vulnerabilities[]`` entry to a :class:`Vulnerability`."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available.",
        )

        score: float | None = None
        severity: str | None = None
        version: str | None = None
        metrics = cve.get("metrics", {})
        # Prefer the newest CVSS version available.
        for key, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                           ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key)
            if not entries:
                continue
            # Prefer NVD's own ("Primary") assessment over a CNA's.
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            version = label
            break

        # CVSS v2 has no "Critical" band, so derive the label from the score
        # for consistency across versions.
        if version == "2.0" or not severity:
            severity = severity_from_score(score)

        return Vulnerability(
            cve_id=cve_id,
            description=description.strip(),
            cvss_score=score,
            severity=severity.upper(),
            cvss_version=version,
            published=cve.get("published"),
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )

    def search(self, product: str, version: str | None = None) -> list[Vulnerability]:
        """
        Look up CVEs for a product/version.

        Args:
            product: Product name as identified from the banner (e.g. ``"OpenSSH"``).
            version: Version string (e.g. ``"7.4"``). Strongly recommended:
                searching a bare product name returns every CVE ever filed
                against it.

        Returns:
            Vulnerabilities sorted by CVSS score (highest first), capped at
            ``max_results``. Empty on no results or API failure.
        """
        keyword = " ".join(filter(None, [KEYWORD_ALIASES.get(product, product), version])).strip()
        if not keyword:
            return []

        cache_key = keyword.lower()
        cached = self._cache_get(cache_key)
        if cached is None:
            logger.debug("Querying NVD for '%s'", keyword)
            data = self._request(keyword)
            if data is None:
                return []  # Don't cache failures so a later run can retry.
            vulns = [self._parse_cve(item) for item in data.get("vulnerabilities", [])]
            cached = [v.to_dict() for v in vulns]
            self._cache_put(cache_key, cached)
        else:
            logger.debug("Cache hit for '%s'", keyword)

        results = [Vulnerability(**v) for v in cached]
        results.sort(key=lambda v: (v.cvss_score or 0.0, SEVERITY_ORDER.get(v.severity, -1)), reverse=True)
        return results[: self.max_results]


def lookup_cves(product: str, version: str | None = None, max_results: int = 10) -> list[Vulnerability]:
    """Convenience wrapper: one-off lookup using a default :class:`CVELookup`."""
    return CVELookup(max_results=max_results).search(product, version)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.cve_lookup <product> [version]")
        sys.exit(1)
    for vuln in lookup_cves(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None):
        score = f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "n/a"
        print(f"{vuln.cve_id:<18} {score:>4}  {vuln.severity:<9} {vuln.description[:90]}")
