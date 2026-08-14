# SentryOps — Infrastructure Vulnerability Scanner Documentation

## 1. Executive Summary

**SentryOps** is a modular DevSecOps tool written in Python. It categorizes infrastructure vulnerability auditing across three target domains:
* **Host**: Linux system packages (`dpkg` for Debian/Ubuntu, `rpm` for RHEL/CentOS/Fedora).
* **Application**: Application dependency manifests (`requirements.txt` for Python/PyPI, `package.json` for Node.js/npm).
* **Container**: Container base images (`Dockerfile`).

All package discoveries are normalized into a common `Dependency` data structure containing `source` and `location` attributes. Findings are cross-referenced against the **OSV.dev API**, hydrated with CVSS v3.1 severity vectors, evaluated with release-scoped version matching and `dpkg --compare-versions`, and rendered as **Human-Readable CLI reports** or **Machine-Readable JSON artifacts**.

---

## 2. Target Domains & CLI Command Reference

### Architecture Map

```text
SentryOps
│
├── Host Domain (sentryops scan host)
│   ├── dpkg.py          --> Scans Debian/Ubuntu system packages (dpkg-query)
│   ├── rpm.py           --> Scans RHEL/Fedora/CentOS system packages (rpm -qa)
│   └── detector.py      --> Distro detector (/etc/os-release) & host scanner
│
├── Application Domain (sentryops scan app / sentryops scan dependencies)
│   ├── requirements.py  --> Parses Python PyPI dependencies (requirements.txt)
│   └── package_json.py  --> Parses Node.js npm dependencies (package.json)
│
└── Container Domain (sentryops scan container / sentryops scan docker)
    └── dockerfile.py    --> Parses Container base images (Dockerfile)
```

### Complete Command & Alias Matrix

| Target Command | Aliases | Target Domain Scanned | Description |
| :--- | :--- | :--- | :--- |
| **`sentryops scan host`** | `host` | **Host System** | Scans installed Linux OS packages using system package manager (`dpkg` or `rpm`). |
| **`sentryops scan app`** | `dependencies`, `application` | **Application** | Scans application manifests (`requirements.txt`, `package.json`). |
| **`sentryops scan container`**| `docker` | **Container** | Scans base images specified in `Dockerfile` manifests. |
| **`sentryops scan all`** | `all` *(Default)* | **All 3 Domains** | Unified multi-domain scan across Host, Application, and Container targets. |

---

## 3. CLI Output Flags & Formatting Options

SentryOps provides dual-level reporting (Human-Readable terminal display and Machine-Readable JSON):

| Flag / Option | Short Flag | Values / Syntax | Description |
| :--- | :--- | :--- | :--- |
| **`--output`** | **`-o`** | `text` *(default)* | Outputs human-readable terminal report with summary counts and critical findings. |
| **`--output`** | **`-o`** | `json` | Outputs formatted machine-readable JSON to stdout. |
| **`--output`** | **`-o`** | `<filepath.json>` | Saves structured JSON report to specified file path (e.g. `-o report.json`). |
| **`--format`** | **`-f`** | `text` \| `json` | Explicitly overrides the output format rendering. |

### Command Examples

```bash
# 1. Human-Readable terminal scan for host packages
sentryops scan host

# 2. Human-Readable terminal scan for application dependencies (alias)
sentryops scan dependencies

# 3. Machine-Readable JSON stdout for automation pipelines
sentryops scan app --output json

# 4. Save JSON report to custom file path while displaying terminal summary
sentryops scan all --output custom_report.json

# 5. Explicit format option
sentryops scan host --format json
```

---

## 4. Normalized Core Data Model

All domain scanners normalize package discoveries into the `Dependency` dataclass defined in [`scanner/models.py`](file:///home/takaya/Desktop/SentryOps/scanner/models.py):

```python
@dataclass(slots=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    source: str      # e.g., "dpkg", "rpm", "requirements.txt", "package.json", "Dockerfile"
    location: str    # e.g., "host", "./requirements.txt", "./package.json", "./Dockerfile"
```

### Domain & Ecosystem Mapping

| Domain Category | Scanner Module | Ecosystem String | Source | Location |
| :--- | :--- | :--- | :--- | :--- |
| **Host** | [`scanner/host/dpkg.py`](file:///home/takaya/Desktop/SentryOps/scanner/host/dpkg.py) | `Debian:<ver>` / `Ubuntu:<ver>` | `dpkg` | `host` |
| **Host** | [`scanner/host/rpm.py`](file:///home/takaya/Desktop/SentryOps/scanner/host/rpm.py) | `RHEL:<ver>` / `Fedora:<ver>` | `rpm` | `host` |
| **Application** | [`scanner/application/requirements.py`](file:///home/takaya/Desktop/SentryOps/scanner/application/requirements.py) | `PyPI` | `requirements.txt` | `./requirements.txt` |
| **Application** | [`scanner/application/package_json.py`](file:///home/takaya/Desktop/SentryOps/scanner/package_json.py) | `npm` | `package.json` | `./package.json` |
| **Container** | [`scanner/container/dockerfile.py`](file:///home/takaya/Desktop/SentryOps/scanner/container/dockerfile.py) | `docker` | `Dockerfile` | `./Dockerfile` |

---

## 5. Vulnerability Engine & Matching Mechanics ([scanner/osv/client.py](file:///home/takaya/Desktop/SentryOps/scanner/osv/client.py))

### Key Subsystems

1. **Ecosystem-Scoped Matching (`evaluate_affected_range`)**:
   * Scopes vulnerability evaluation strictly to the target ecosystem (e.g. `Debian:13`). Advisories for other releases (`Debian:11`, `Debian:12`) are ignored to prevent release leakage and false positives.

2. **Debian Version Semantics (`compare_debian_versions`)**:
   * Uses `dpkg --compare-versions <installed> lt <fixed>` via subprocess to handle Debian epochs (`2:`), revisions (`-7`), and backport tags (`~deb13u2`).

3. **CVSS v3.1 Base Score Calculator ([scanner/formatter.py](file:///home/takaya/Desktop/SentryOps/scanner/formatter.py))**:
   * Implements the FIRST.org CVSS v3.1 formula to compute exact numerical base scores (0.0 to 10.0) from CVSS vector strings, categorizing findings into `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW`.

4. **Match Reason Diagnostics**:
   * Attaches an explicit `match_reason` string to every finding (e.g., `"Installed 1.7.1-6+deb13u2 < fixed 1.7.1-6+deb13u3 in Debian:13"`).

5. **Batched API Processing (`check_dependencies`)**:
   * Utilizes `https://api.osv.dev/v1/querybatch` to query up to 1,000 packages per HTTP request, preventing rate-limiting issues across large package sets.

6. **Local Disk Caching (`.sentryops_cache.json`)**:
   * Caches raw OSV responses under `{ecosystem}:{name}=={version}` for sub-second repeat scans.

---

## 6. Output Format Specification

### Machine-Readable JSON Schema (`--output json`)

```json
{
  "scan": {
    "id": "scan-20260814-001",
    "started_at": "2026-08-14T15:40:09Z",
    "duration": 0.1,
    "target": "application",
    "type": "app"
  },
  "summary": {
    "packages": 1,
    "vulnerabilities": 3,
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 0
  },
  "findings": [
    {
      "cve_id": "GHSA-9hjg-9r4m-mvj7",
      "package": "requests",
      "installed": "2.31.0",
      "fixed": "2.32.4",
      "severity": "MEDIUM",
      "ecosystem": "PyPI",
      "match_reason": "Installed 2.31.0 < fixed 2.32.4 in PyPI"
    }
  ]
}
```
