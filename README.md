# 🛡️ PortRecon

A network vulnerability scanner written in Python. PortRecon finds open TCP ports on a target, fingerprints the services on them from their banners, and checks the NIST National Vulnerability Database (NVD) for known CVEs. It writes the results to an HTML report color-coded by severity and to a JSON file.

> **⚠️ Legal and ethical use only.** Read the **Legal & ethical disclaimer** at the end before you use this tool.

---

## ✨ Features

| Stage | What it does |
|---|---|
| **Port scanning** | Multi-threaded TCP connect scan (`socket` + `ThreadPoolExecutor`). The timeout and thread count can both be set. It accepts ranges and lists (`1-1000`, `22,80,443`, `1-100,8080`). |
| **Banner grabbing** | Reads passive banners (SSH, FTP, SMTP, MySQL handshake) and sends protocol probes when a service stays quiet (HTTP `HEAD`, over TLS for 443/8443). Regex signatures pull out the product and version, e.g. `OpenSSH 7.4` or `Apache httpd 2.4.29`. |
| **CVE lookup** | Keyword search against the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities). It returns the CVE ID, description, CVSS score and severity. A thread-safe sliding-window rate limiter and a 24-hour on-disk cache limit the number of API calls. |
| **Reporting** | A self-contained HTML report (light and dark mode, severity color-coding, links to NVD) and a raw JSON export, both timestamped under `reports/`. |
| **Safety** | Shows a legal warning and requires an explicit `yes` before any scan. All untrusted data (banners, CVE text) is HTML-escaped, so a malicious service can't inject script into the report. |

It uses only the standard library plus `requests` (for the NVD API). It doesn't depend on nmap or any other external scanning library.

## 📦 Installation

Requires **Python 3.10+**.

```bash
git clone https://github.com/KrishivSharma45/portrecon.git
cd portrecon
pip install -r requirements.txt
```

**Optional:** get a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) to raise the rate limit from 5 to 50 requests per 30 seconds:

```bash
export NVD_API_KEY="your-key"        # Linux / macOS
setx NVD_API_KEY "your-key"          # Windows (restart the terminal afterwards)
```

## 🚀 Usage

```bash
python main.py --target <IP or hostname> --ports <range> [--threads N] [--output NAME]
```

| Option | Default | Description |
|---|---|---|
| `-t`, `--target` | *required* | Target IPv4 address or hostname |
| `-p`, `--ports` | `1-1000` | Ports to scan: `1-1000`, `22,80,443`, `1-100,8080-8090` |
| `--threads` | `100` | Number of concurrent scanning threads (1–1000) |
| `--timeout` | `1.0` | Per-port connect timeout in seconds |
| `-o`, `--output` | `portrecon_<ip>` | Base name for the report files (a timestamp is appended) |
| `--max-cves` | `10` | Maximum CVEs reported per service, highest CVSS score first |
| `--no-cve` | off | Skip the NVD lookup and only scan and fingerprint |
| `-v`, `--verbose` | off | Debug logging |

### 💡 Examples

```bash
# Scan the top 1000 ports of a Metasploitable VM on a host-only network
python main.py --target 192.168.56.101 --ports 1-1000 --output metasploitable

# Scan a few specific ports with more threads and a shorter timeout
python main.py -t 10.10.10.5 -p 21,22,80,443,3306,8080 --threads 200 --timeout 0.5

# Scan all ports, without CVE lookups
python main.py -t 192.168.1.50 -p 1-65535 --threads 500 --no-cve
```

### 🖥️ Sample output

```text
[*] Target: 192.168.56.101 (192.168.56.101)  |  Ports: 1000  |  Threads: 100  |  Timeout: 1.0s
[*] Scanning... 1000/1000 ports checked (100.0%)
[+] Open ports: 21, 22, 80
[*] Grabbing service banners...
[+] 21/tcp  ftp          vsftpd 2.3.4
[+] 22/tcp  ssh          OpenSSH 7.4
[+] 80/tcp  http         Apache httpd 2.4.29
[*] Querying the NIST NVD for known vulnerabilities...
[+] Port 21: 1 CVE(s) found (1 critical)
[+] Port 22: 6 CVE(s) found (4 high, 2 medium)
[+] Port 80: 2 CVE(s) found (1 critical, 1 medium)

================================================================
 SCAN SUMMARY
================================================================
 PORT      SERVICE       PRODUCT                       CVEs
 21/tcp    ftp           vsftpd 2.3.4                     1
 22/tcp    ssh           OpenSSH 7.4                      6
 80/tcp    http          Apache httpd 2.4.29              2
----------------------------------------------------------------
 Open ports found:      3
 Vulnerabilities found: 9
 HTML report:           reports/metasploitable_20260924_171956.html
 JSON report:           reports/metasploitable_20260924_171956.json
================================================================
```

### 🧩 Running modules individually

Each stage is a standalone module that you can run or import on its own:

```bash
python -m scanner.port_scanner 127.0.0.1 1-1024      # port scan only
python -m scanner.banner_grabber 127.0.0.1 22,80     # fingerprint specific ports
python -m scanner.cve_lookup OpenSSH 7.4             # CVE lookup only
python -m scanner.report_generator                   # render a demo report
```

```python
from scanner.port_scanner import scan_ports
from scanner.banner_grabber import grab_banners
from scanner.cve_lookup import CVELookup

open_ports = scan_ports("192.168.56.101", range(1, 1025), threads=200)
services = grab_banners("192.168.56.101", open_ports)
cves = CVELookup().search("OpenSSH", "7.4")
```

## 🧪 Running tests

The test suite covers every module. It uses local sockets and a stubbed NVD API, so it needs no network access and never scans anything external.

```bash
pip install -r requirements-dev.txt
pytest
```

## 📁 Project structure

```text
portrecon/
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py      # Multi-threaded TCP connect scan and port-range parsing
│   ├── banner_grabber.py    # Banner retrieval, protocol probes, service fingerprinting
│   ├── cve_lookup.py        # NVD API client with rate limiting and caching
│   └── report_generator.py  # HTML and JSON report output
├── tests/                   # pytest suite (no network required)
├── main.py                  # CLI entry point and pipeline orchestration
├── requirements.txt
├── requirements-dev.txt     # requirements.txt + pytest
├── pytest.ini
├── LICENSE
└── README.md
```

## ⚙️ How it works

1. **TCP connect scan.** For each port, a worker thread calls `connect_ex()`. A completed three-way handshake means the port is open. This scan type needs no root or raw-socket privileges. The trade-off is that it's noisier than a SYN scan, because the target logs full connections.
2. **Banner grabbing.** PortRecon reconnects to each open port and waits briefly for the service to speak first. If it stays silent, PortRecon sends an HTTP `HEAD` probe, over TLS on HTTPS ports. The response is matched against an ordered list of regex signatures.
3. **CVE lookup.** The product and version are sent to the NVD as a keyword search. Results are ranked by CVSS score. PortRecon uses the newest CVSS version available (v4.0 → v3.1 → v3.0 → v2.0) and prefers NVD's own "Primary" score. Services without a detected version are skipped, because searching a bare product name returns thousands of irrelevant CVEs.
4. **Reporting.** Findings are combined into one structured dict. It is written out as JSON and rendered as HTML.

## ⚠️ Limitations

- **Keyword matching is heuristic.** It can report false positives, such as CVEs that mention a version only as the fix version ("before 7.4"). It can also miss CVEs that are described in different words. It also doesn't know about vendor backports: Ubuntu's `OpenSSH 7.4` may already be patched. Treat the results as leads to verify, not confirmed vulnerabilities.
- IPv4 and TCP only. There is no UDP scanning.
- Services that give no banner and don't answer HTTP are reported as `unknown`.

## ⚖️ Legal & ethical disclaimer

**Only scan systems you own or have explicit, written permission to test.**

Unauthorized port scanning and vulnerability probing may be illegal in your jurisdiction. Relevant laws include the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act and equivalent laws elsewhere. It may also violate your ISP's or cloud provider's terms of service. Permission to access a network is not the same as permission to scan it.

Good legal targets for practice:

- Your own home lab or virtual machines
- Intentionally vulnerable VMs such as [Metasploitable 2/3](https://docs.rapid7.com/metasploit/metasploitable-2/), on a host-only network
- Lab machines on platforms such as [TryHackMe](https://tryhackme.com) and [Hack The Box](https://www.hackthebox.com), within each platform's rules
- `scanme.nmap.org`, which the Nmap project explicitly permits for light scanning

This tool is provided for educational and authorized security-testing purposes. The author accepts no liability for misuse or damage. **You are responsible for your actions.**

## 👨‍💻 Author

**Krishiv Sharma**

- 🐙 GitHub: [@KrishivSharma45](https://github.com/KrishivSharma45)
- 💼 LinkedIn: [Krishiv Sharma](https://www.linkedin.com/in/krishiv-sharma-043335381)

If you found this project useful, consider giving it a ⭐ on GitHub!
