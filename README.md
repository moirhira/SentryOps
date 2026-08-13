# SentryOps — Infrastructure & Application Vulnerability Scanner

**SentryOps** is a lightweight, agentless DevSecOps vulnerability scanner built in Python. It scans system packages, application manifests, and container base images, cross-references dependencies against the [OSV.dev API](https://osv.dev) in batch queries, calculates exact CVSS v3.1 base scores, and generates both **Human-Readable** CLI reports and **Machine-Readable JSON** artifacts.

---

## 🏛️ Architecture

```mermaid
flowchart TD
    subgraph Input["Scan Targets"]
        H["Host System<br/>(/etc/os-release + dpkg/rpm)"]
        A["Application Manifests<br/>(requirements.txt, package.json)"]
        C["Container Images<br/>(Dockerfile base images)"]
    end

    subgraph Core["SentryOps Core Engine"]
        DP["Dependency Parser<br/>(scanner/host, scanner/app, scanner/container)"]
        CACHE[".sentryops_cache.json<br/>(Local Batch Cache)"]
        OSV["OSV.dev Client<br/>(Batch API: api.osv.dev/v1/query)"]
        CVSS["CVSS v3.1 Engine<br/>(Base Score Calculator & Severity Classifier)"]
        FMT["Output Formatter<br/>(scanner/formatter.py)"]
    end

    subgraph Output["Output Levels"]
        HUMAN["Human-Readable CLI<br/>(sentryops scan host)"]
        JSON["Machine-Readable JSON<br/>(sentryops scan host --output json)"]
    end

    H --> DP
    A --> DP
    C --> DP
    DP --> CACHE
    CACHE -- Cache Miss --> OSV
    OSV -- Raw Vuln Data --> CACHE
    CACHE -- Vuln Details --> CVSS
    CVSS --> FMT
    FMT --> HUMAN
    FMT --> JSON
```

---

## 🌐 The Three Scan Domains

SentryOps categorizes infrastructure into three distinct scan domains:

### 1. Host Domain (`sentryops scan host`)
- **System Detection**: Auto-parses `/etc/os-release` to detect OS name, version, architecture, and package manager (`dpkg` or `rpm`).
- **Ecosystem Mapping**: Maps distro family and release versions to OSV target ecosystems (e.g., `Debian:12`, `Debian:13`, `Ubuntu:24.04`).
- **Package Inventory**: Scans installed system packages via native package manager commands (`dpkg-query` or `rpm -qa`).

### 2. Application Domain (`sentryops scan app`)
- **Manifest Parsing**: Scans project workspace files for application dependency manifests:
  - `requirements.txt` (Python PyPI packages)
  - `package.json` / `package-lock.json` (Node.js NPM packages)
- **Pinned Version Resolution**: Extracts package names and exact installed version strings (`requests==2.31.0`).

### 3. Container Domain (`sentryops scan container`)
- **Dockerfile Inspection**: Parses `Dockerfile` manifests to identify base container images (e.g., `FROM ubuntu:24.04`, `FROM node:18-alpine`).
- **Image Vulnerability Checking**: Cross-references base image versions against known base distribution advisories.

---

## 📊 CVSS Scoring Approach & Severity Bucketing

SentryOps does **not** rely on naive string matching for severity classification. Instead, it extracts CVSS vector strings and calculates exact numerical base scores according to the official **FIRST.org CVSS v3.1 Specification**.

### CVSS Base Score Calculation

For CVSS v3.0 / v3.1 vectors (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`):

1. **Impact Sub-Score (ISS)**:
   $$\text{ISS} = 1 - ( (1 - C) \times (1 - I) \times (1 - A) )$$
2. **Impact Metric**:
   $$\text{Impact} = \begin{cases} 6.42 \times \text{ISS} & \text{if Scope (S) is Unchanged (U)} \\ 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15} & \text{if Scope (S) is Changed (C)} \end{cases}$$
3. **Exploitability Sub-Score**:
   $$\text{Exploitability} = 8.22 \times AV \times AC \times PR \times UI$$
4. **Base Score Calculation**:
   $$\text{Base Score} = \min\left( \text{Impact} + \text{Exploitability}, 10.0 \right) \quad \text{(rounded up to 1 decimal place)}$$

### Severity Bucketing Matrix

| Severity Level | CVSS Base Score Range | Example Metric Vectors |
| :--- | :--- | :--- |
| **CRITICAL** | **9.0 – 10.0** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Score: 9.8) |
| **HIGH** | **7.0 – 8.9** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Score: 7.5) |
| **MEDIUM** | **4.0 – 6.9** | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (Score: 5.3) |
| **LOW** | **0.1 – 3.9** | `AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N` (Score: 2.5) |

---

## 📌 The Debian-Testing Fixed-Version Caveat

When running scans on rolling or pre-release testing Linux distributions (e.g., **Debian 13 Trixie**), findings may display:

```text
DEBIAN-CVE-2026-14266
Package:   7zip
Installed: 25.01+dfsg-1~deb13u2
Fixed:     None
Severity:  HIGH
```

### Why `Fixed: None` Appears
1. **Upstream Advisory Lifecycle**: In Debian testing/unstable tracks, security patches are staged in `unstable` (Sid) before migrating to `testing`.
2. **OSV Range Semantics**: The OSV database schema only emits a `{ "fixed": "<version>" }` event when a backported fix is explicitly tagged for that specific release branch (`Debian:13`). If a fix has not yet landed in the testing branch, the range remains un-closed, resulting in `Fixed: None`.
3. **Stable Distros & PyPI**: For PyPI, NPM, and stable Debian releases (e.g., `Debian:10`, `Debian:11`, `Debian:12`), exact fix version numbers (`Fixed: 2.32.4`, `Fixed: 2:9.2.0119-1`) are extracted and populated.

---

## 🚀 Quickstart & Usage

### Human-Readable Terminal Output (Default)

```bash
sentryops scan host
```
```text
SentryOps Security Scanner
───────────────────────────

Target:   localhost
Type:     Linux Host
OS:       Debian GNU/Linux 13
Manager:  dpkg

Packages scanned: 1897

Vulnerabilities
───────────────────────────

CRITICAL  15
HIGH      109
MEDIUM    154
LOW       52

CRITICAL & HIGH FINDINGS

DEBIAN-CVE-2026-6653
Package:   libxml2
Installed: 2.12.7+dfsg+really2.9.14-2.1+deb13u3
Fixed:     2.14.5+dfsg-0.1
Severity:  CRITICAL
...
───────────────────────────
Scan completed in 0.1s (cached)
```

### Machine-Readable JSON Output

```bash
sentryops scan host --output json
```
```json
{
  "scan": {
    "id": "scan-20260813-001",
    "started_at": "2026-08-13T14:30:00Z",
    "duration": 0.1,
    "target": "localhost",
    "type": "host"
  },
  "summary": {
    "packages": 1897,
    "vulnerabilities": 330,
    "critical": 15,
    "high": 109,
    "medium": 154,
    "low": 52
  },
  "findings": [
    {
      "cve_id": "DEBIAN-CVE-2026-6653",
      "package": "libxml2",
      "installed": "2.12.7+dfsg+really2.9.14-2.1+deb13u3",
      "fixed": "2.14.5+dfsg-0.1",
      "severity": "CRITICAL"
    }
  ]
}
```

---

## ⚠️ Known Limitations

- **Package Managers**: Currently supports **`dpkg`** (Debian, Ubuntu, Mint, Kali) and **`rpm`** (RHEL, Fedora, CentOS, Rocky, AlmaLinux, Amazon Linux). Does not currently support `pacman` (Arch Linux) or `apk` (Alpine Linux).
- **Single-Distro Host Scope**: Host scans evaluate the primary operating system distribution installed on the target machine.
- **Offline & Rate-Limit Caching**: Queries OSV.dev in 1000-package batches via HTTP POST API; sub-second repeat scans rely on the local cache file (`.sentryops_cache.json`).

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
