# SentryOps — Infrastructure Vulnerability Scanner Documentation

## 1. Executive Summary

**SentryOps** is a modular DevSecOps tool written in Python. It categorizes infrastructure vulnerability auditing across three target domains:
* **Host**: Linux system packages (`dpkg` for Debian/Ubuntu, `rpm` for RHEL/CentOS/Fedora).
* **Application**: Application dependency manifests (`requirements.txt` for Python/PyPI, `package.json` for Node.js/npm).
* **Container**: Container base images (`Dockerfile`).

All package discoveries are normalized into a common `Dependency` data structure containing `source` and `location` attributes. Findings are cross-referenced against the **OSV.dev API**, hydrated with CVSS severity vectors, filtered to exclude historical noise (`Debian Urgency: unimportant`), and exported to `report.json`.

---

## 2. Target Domain & CLI Commands

```text
SentryOps
│
├── Host (sentryops scan host)
│   ├── dpkg.py          --> Scans Debian/Ubuntu system packages (dpkg-query)
│   ├── rpm.py           --> Scans RHEL/Fedora/CentOS system packages (rpm -qa)
│   └── detector.py      --> Distro detector (/etc/os-release) & host scanner
│
├── Application (sentryops scan dependencies)
│   ├── requirements.py  --> Parses Python PyPI dependencies (requirements.txt)
│   └── package_json.py  --> Parses Node.js npm dependencies (package.json)
│
└── Container (sentryops scan container)
    └── dockerfile.py    --> Parses Container base images (Dockerfile)
```

---

## 3. Normalized Core Data Model

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
| **Application** | [`scanner/application/package_json.py`](file:///home/takaya/Desktop/SentryOps/scanner/application/package_json.py) | `npm` | `package.json` | `./package.json` |
| **Container** | [`scanner/container/dockerfile.py`](file:///home/takaya/Desktop/SentryOps/scanner/container/dockerfile.py) | `docker` | `Dockerfile` | `./Dockerfile` |

---

## 4. Vulnerability Engine & OSV Integration ([scanner/osv/client.py](file:///home/takaya/Desktop/SentryOps/scanner/osv/client.py))

### Key Subsystems

1. **OSV Ecosystem Mapping (`get_osv_ecosystem`)**:
   * Maps detected host distro info (`os_id`, `version`) to OSV versioned ecosystems (e.g. `Debian:13` or `Ubuntu:22.04`).

2. **Debian Version Normalization (`normalize_debian_version`)**:
   * Strips backport/build suffixes (`25.01+dfsg-1~deb13u2` -> `25.01`) for consistent version representation.

3. **Batched API Processing (`check_dependencies`)**:
   * Utilizes `https://api.osv.dev/v1/querybatch` to query up to 1,000 packages per HTTP request, preventing rate-limiting issues across large package sets.

4. **Detail Hydration & Location Tracking (`parse_vuln_details`)**:
   * Fetches `/v1/vulns/{id}` for hits to extract `summary` and top-level `CVSS_V3`/`CVSS_V4` vectors, attaching `source` and `location` metadata to each finding.

5. **Actionable Vulnerability Filtering (`is_actionable`)**:
   * Filters out historical/disputed `Debian Urgency: unimportant` records. Only CVSS-scored entries are flagged as actionable.

6. **Local Disk Caching**:
   * Saves responses to [.sentryops_cache.json](file:///home/takaya/Desktop/SentryOps/.sentryops_cache.json) under `{ecosystem}:{name}=={version}`.

---

## 5. Output & Report Specification

Running `python3 scanner/main.py scan <target>` scans the selected domain(s) and produces [report.json](file:///home/takaya/Desktop/SentryOps/report.json):

```json
{
  "timestamp": "2026-08-11T11:18:42.457644+00:00",
  "host": {
    "os_name": "Debian GNU/Linux",
    "os_id": "debian",
    "version": "13",
    "architecture": "x86_64"
  },
  "summary": {
    "total_packages_scanned": 1898,
    "packages_scanned_by_category": {
      "host": 1897,
      "application": 1,
      "container": 0
    },
    "total_actionable_cves": 333
  },
  "findings": {
    "host": {
      "7zip==25.01+dfsg-1~deb13u2": [
        {
          "id": "DEBIAN-CVE-2022-47111",
          "summary": "7-Zip 22.01 does not report an error for certain invalid xz files...",
          "severity": "CVSS_V3: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "source": "dpkg",
          "location": "host"
        }
      ]
    },
    "application": {
      "requests==2.31.0": [
        {
          "id": "GHSA-9hjg-9r4m-mvj7",
          "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
          "severity": "CVSS_V3: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
          "source": "requirements.txt",
          "location": "requirements.txt"
        }
      ]
    },
    "container": {}
  }
}
```

---

## 6. CLI Execution Guide

```bash
# Scan Linux OS installed packages
python3 scanner/main.py scan host

# Scan application dependency manifests (requirements.txt, package.json)
python3 scanner/main.py scan dependencies

# Scan container base image manifests (Dockerfile)
python3 scanner/main.py scan container

# Scan all target domains (default)
python3 scanner/main.py scan all
```
