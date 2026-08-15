# SentryOps — Complete System Documentation & Technical Reference

This is the comprehensive, exhaustive technical reference for **SentryOps** — a modular, multi-domain infrastructure security scanner built in Python.

This document explains **every module, class, function, algorithm, data schema, CVSS math formula, CLI command, and design decision** across the SentryOps codebase so you can answer any architectural or operational question with total mastery.

---

## 📋 Table of Contents
1. [Project Overview & Architecture](#1-project-overview--architecture)
2. [Project Directory & File Map](#2-project-directory--file-map)
3. [Core Data Model (`scanner/models.py`)](#3-core-data-model-scannermodelspy)
4. [Package Discovery Domain Modules](#4-package-discovery-domain-modules)
   - [Host OS Scanner (`scanner/host/`)](#host-os-scanner-scannerhost)
   - [Application Manifest Scanner (`scanner/application/`)](#application-manifest-scanner-scannerapplication)
   - [Container Base Image Scanner (`scanner/container/`)](#container-base-image-scanner-scannercontainer)
5. [Vulnerability Engine & Matching Core (`scanner/osv/`)](#5-vulnerability-engine--matching-core-scannerosv)
   - [Ecosystem & Version Matching (`scanner/osv/version.py`)](#ecosystem--version-matching-scannerosvversionpy)
   - [OSV API Client & Cache System (`scanner/osv/client.py`)](#osv-api-client--cache-system-scannerosvclientpy)
6. [Scoring & Output Formatter (`scanner/formatter.py`)](#6-scoring--output-formatter-scannerformatterpy)
   - [CVSS v3.1 Mathematical Scoring Formula](#cvss-v31-mathematical-scoring-formula)
   - [Human-Readable Terminal & JSON Report Renderers](#human-readable-terminal--json-report-renderers)
7. [CLI Controller (`scanner/cli.py`) & Commands](#7-cli-controller-scannerclipy--commands)
8. [Automated Regression Test Suite (`tests/test_engine.py`)](#8-automated-regression-test-suite-teststest_enginepy)
9. [Interview & Audit Cheat-Sheet](#9-interview--audit-cheat-sheet)

---

## 1. Project Overview & Architecture

SentryOps scans software assets across **3 target domains** (Host OS, Application Manifests, Container Images), normalizes discovered items into a unified `Dependency` representation, queries the **OSV.dev REST API** in high-throughput 1,000-package batches, evaluates vulnerability ranges using **ecosystem-scoped semantics** and system `dpkg --compare-versions`, and generates structured reports.

### Visual Architecture Diagram

```mermaid
flowchart TD
    A[CLI User / CI Pipeline] -->|sentryops scan host/app/container/all| B[CLI Controller scanner/cli.py]
    
    subgraph Package Discovery
        B --> C1[Host Detector scanner/host/detector.py]
        B --> C2[App Parsers scanner/application/]
        B --> C3[Container Parser scanner/container/dockerfile.py]
        
        C1 -->|dpkg-query / rpm -qa| D1[dpkg.py / rpm.py]
        C2 -->|requirements.txt| D2[requirements.py]
        C2 -->|package.json| D3[package_json.py]
        C3 -->|Dockerfile FROM| D4[dockerfile.py]
    end
    
    D1 & D2 & D3 & D4 -->|Dependency dataclass| E[OSV Batch Engine scanner/osv/client.py]
    
    subgraph Vulnerability Matching Engine
        E -->|Check Cache| F1[.sentryops_cache.json]
        E -->|Batch Query POST| F2[OSV.dev REST API]
        E -->|Evaluate Ranges| G[Range Evaluator scanner/osv/version.py]
        G -->|Debian Version Compare| H[dpkg --compare-versions]
    end
    
    G -->|EvaluationResult| I[Report Formatter scanner/formatter.py]
    
    subgraph Output Generation
        I -->|CVSS v3.1 Math| J[Base Score Math]
        I -->|Human Box UI| K[Terminal Output]
        I -->|JSON Schema| L[report.json / Stdout JSON]
    end
```

---

## 2. Project Directory & File Map

| Path | Purpose / Description |
| :--- | :--- |
| **`sentryops`** | Shell entrypoint script pointing to `scanner.cli:main()`. |
| **`setup.py`** | Package setup script installing `sentryops` as a global CLI command. |
| **`scanner/`** | Main package root directory containing all submodules. |
| ├── **`models.py`** | Core `Dependency` dataclass schema. |
| ├── **`cli.py`** | Argparse CLI entrypoint, command routing, and timing logic. |
| ├── **`formatter.py`** | FIRST.org CVSS v3.1 mathematical score calculator and report renderers. |
| ├── **`host/`** | Host OS discovery package. |
| │   ├── **`detector.py`** | OS identification via `/etc/os-release` and host scanning coordinator. |
| │   ├── **`dpkg.py`** | Scans Debian/Ubuntu system packages via `dpkg-query`. |
| │   └── **`rpm.py`** | Scans RHEL/CentOS/Fedora system packages via `rpm -qa`. |
| ├── **`application/`** | Application dependency parsing package. |
| │   ├── **`requirements.py`** | Python `requirements.txt` parser. |
| │   └── **`package_json.py`** | Node.js `package.json` parser. |
| ├── **`container/`** | Container base image parsing package. |
| │   └── **`dockerfile.py`** | Dockerfile `FROM` directive parser. |
| └── **`osv/`** | Vulnerability query & version evaluation engine. |
|     ├── **`version.py`** | `dpkg --compare-versions` wrapper, event range parser, `EvaluationResult`. |
|     └── **`client.py`** | OSV REST API batch client, local cache manager (`.sentryops_cache.json`). |
| **`tests/`** | Automated test suite. |
| └── **`test_engine.py`** | 10-case automated regression test suite (`unittest`). |

---

## 3. Core Data Model (`scanner/models.py`)

All discovery modules normalize scanned software packages into the `Dependency` dataclass:

```python
from dataclasses import dataclass

@dataclass(slots=True)
class Dependency:
    name: str          # e.g., "openssl", "requests", "ubuntu"
    version: str | None # e.g., "3.0.13-1", "2.31.0", "22.04"
    ecosystem: str     # e.g., "dpkg", "rpm", "PyPI", "npm", "docker"
    source: str        # e.g., "dpkg", "requirements.txt", "package.json", "Dockerfile"
    location: str      # e.g., "host", "./requirements.txt", "./Dockerfile"
```

### Why dataclass with `slots=True`?
Using `slots=True` eliminates `__dict__` memory overhead for every package object, speeding up scanning across large package inventories (1,800+ system packages) while reducing memory consumption.

---

## 4. Package Discovery Domain Modules

### Host OS Scanner (`scanner/host/`)

#### 1. `scanner/host/detector.py`
- **`HostInfo` Dataclass**: Stores `os_name`, `os_id` (e.g. `"debian"`), `version` (e.g. `"13"`), `architecture`.
- **`detect_host_os() -> HostInfo | None`**:
  Reads `/etc/os-release` line-by-line to parse `ID=`, `VERSION_ID=`, and `PRETTY_NAME=`. Returns a populated `HostInfo` object.
- **`scan_host_packages(host_info) -> list[Dependency]`**:
  Determines system package manager:
  - If `host_info.os_id` is in `("debian", "ubuntu", "mint", "kali", "pop")`, calls `scanner.host.dpkg.scan_dpkg_packages()`.
  - Else calls `scanner.host.rpm.scan_rpm_packages()`.

#### 2. `scanner/host/dpkg.py`
- **`scan_dpkg_packages() -> list[Dependency]`**:
  Runs command: `dpkg-query -W -f='${Package}\t${Version}\n'`.
  Splits output line by line on `\t` into `(pkg_name, pkg_version)`.
  Returns `Dependency(name=pkg_name, version=pkg_version, ecosystem="dpkg", source="dpkg", location="host")`.

#### 3. `scanner/host/rpm.py`
- **`scan_rpm_packages() -> list[Dependency]`**:
  Runs command: `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`.
  Splits output line by line on `\t` into `(pkg_name, pkg_version)`.
  Returns `Dependency(name=pkg_name, version=pkg_version, ecosystem="rpm", source="rpm", location="host")`.

---

### Application Manifest Scanner (`scanner/application/`)

#### 1. `scanner/application/requirements.py`
- **`parse_requirements_txt(filepath="requirements.txt") -> list[Dependency]`**:
  Reads lines from `requirements.txt`. Ignores comments (`#`) and options (`-r`, `-e`).
  Splits package specifiers on `==`, `>=`, `<=`, `~=`.
  Extracts pinned version (e.g. `requests==2.31.0`).
  Returns `Dependency(name="requests", version="2.31.0", ecosystem="PyPI", source="requirements.txt", location=filepath)`.

#### 2. `scanner/application/package_json.py`
- **`parse_package_json(filepath="package.json") -> list[Dependency]`**:
  Parses `package.json` JSON file. Reads `"dependencies"` and `"devDependencies"` dictionaries.
  Strips semver range prefixes (`^`, `~`, `>=`, `v`).
  Returns `Dependency(name=pkg, version=clean_ver, ecosystem="npm", source="package.json", location=filepath)`.

---

### Container Base Image Scanner (`scanner/container/`)

#### 1. `scanner/container/dockerfile.py`
- **`parse_dockerfile(filepath="Dockerfile") -> list[Dependency]`**:
  Reads `Dockerfile`. Scans for lines starting with `FROM`.
  Parses image name and tag (e.g. `FROM ubuntu:22.04` -> `name="ubuntu"`, `version="22.04"`).
  Returns `Dependency(name=img, version=tag, ecosystem="docker", source="Dockerfile", location=filepath)`.

---

## 5. Vulnerability Engine & Matching Core (`scanner/osv/`)

### Ecosystem & Version Matching (`scanner/osv/version.py`)

This module is the core intelligence of SentryOps. It implements **release-isolated matching**, **package-name scoping**, **priority fixed-range evaluation**, and **system Debian version comparison**.

#### 1. Dataclasses & Data Types
- **`EvaluationResult` Dataclass**:
  ```python
  @dataclass(slots=True)
  class EvaluationResult:
      is_affected: bool
      ecosystem: str            # e.g., "Debian:13"
      package_name: str         # e.g., "jq"
      installed_version: str    # e.g., "1.7.1-6+deb13u2"
      range: dict[str, str|None] # {"introduced": "0", "fixed": "1.7.1-6+deb13u3"}
      comparator: str           # "dpkg" or "semver"
  ```
  - **`to_match_dict()` Method**: Returns structured dictionary representation formatted for JSON reports.

#### 2. Debian Version Comparison (`compare_debian_versions`)
```python
def compare_debian_versions(v1: str, op: str, v2: str) -> bool:
    res = subprocess.run(["dpkg", "--compare-versions", v1, op, v2], ...)
    return res.returncode == 0
```
- **Why `dpkg --compare-versions`?**
  Debian package versions use epochs (`2:`), revisions (`-7`), and backport tags (`~deb13u2`). Standard semver libraries or string comparisons fail (e.g., string comparison says `"25.01" < "22.01"` is False, whereas Debian comparison handles epoch/backport rules).

#### 3. Range Parsing (`_parse_event_ranges`)
Converts raw OSV event arrays into `(introduced, fixed, last_affected)` pairs:
- Handles paired events: `[{introduced: "0"}, {fixed: "1.2.3"}]`.
- Handles open-ended ranges: `[{introduced: "0"}]`.
- Handles `last_affected` events: `[{introduced: "0"}, {last_affected: "1.2.2"}]`.

#### 4. Vulnerability Range Evaluator (`evaluate_affected_range`)
```python
def evaluate_affected_range(
    installed_ver: str,
    affected_list: list[dict],
    target_ecosystem: str,
    package_name: str = ""
) -> EvaluationResult | None
```
**Evaluation Algorithm**:
1. **Strict Filtering**: Inspects only `affected` entries where `package.ecosystem == target_ecosystem` AND `package.name == package_name`. Discards advisories from other releases (`Debian:11`, `Debian:12`) and other packages.
2. **Unimportant Urgency Filter**: Ignores entries marked `ecosystem_specific.urgency == "unimportant"` by Debian Security Tracker.
3. **Priority 1 (Fixed Ranges)**:
   - Gathers all ranges defining a `fixed` version `F`.
   - If `installed_ver < F` (evaluated via `dpkg --compare-versions`), returns `EvaluationResult(is_affected=True, range={"introduced": intro, "fixed": F})`.
   - If `installed_ver >= F` for all fixed ranges, marks package as **patched** and returns `None`.
4. **Priority 2 (Open-Ended Ranges)**:
   - If no fixed versions exist across the package's advisories in `target_ecosystem`, evaluates open ranges `[introduced, ∞)` or `[introduced, last_affected]`.

---

### OSV API Client & Cache System (`scanner/osv/client.py`)

#### 1. `get_osv_ecosystem(os_id, version) -> str`
Maps host OS distro ID and version number to official OSV ecosystem string:
- `debian` + `13` -> `"Debian:13"`
- `ubuntu` + `22.04` -> `"Ubuntu:22.04"`
- `rhel` + `9` -> `"Red Hat"`

#### 2. `parse_vuln_details(v, target_ecosystem, installed_ver, package_name) -> dict | None`
Parses raw vulnerability JSON from OSV API:
- Invokes `evaluate_affected_range(installed_ver, v["affected"], target_ecosystem, package_name)`.
- If `eval_result` is `None` (package patched or not affected), returns `None` (discarded).
- If affected, extracts `summary`, CVSS severity strings, sets `"status": "affected"`, `"fixed": fixed_ver or "None"`, and builds structured `"match"` dictionary.

#### 3. `check_dependencies(dependencies, os_id, os_version) -> dict[str, list[dict]]`
High-throughput batch vulnerability query coordinator:
- Checks local disk cache (`.sentryops_cache.json`) under key `{ecosystem}:{name}=={version}`.
- Batches un-cached packages into **1,000-package HTTP POST queries** to `https://api.osv.dev/v1/querybatch`.
- For hits, fetches detailed vulnerability info from `https://api.osv.dev/v1/vulns/{id}`.
- Saves raw responses to `.sentryops_cache.json` for sub-second repeat scans.

---

## 6. Scoring & Output Formatter (`scanner/formatter.py`)

### CVSS v3.1 Mathematical Scoring Formula

SentryOps implements the official **FIRST.org CVSS v3.1 Base Score equation** in `calculate_cvss_score(severity_str)`:

$$\text{CVSS Base Score} = \min(\text{Impact} + \text{Exploitability}, 10.0)$$

#### Sub-equations:
1. **ISS (Impact Sub-Score)**:
   $$\text{ISS} = 1 - (1 - C) \times (1 - I) \times (1 - A)$$
   Where $C, I, A$ are metric values for Confidentiality, Integrity, and Availability (`None=0.0`, `Low=0.22`, `High=0.56`).

2. **Impact**:
   - If Scope is Unchanged (`S:U`):
     $$\text{Impact} = 6.42 \times \text{ISS}$$
   - If Scope is Changed (`S:C`):
     $$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$

3. **Exploitability**:
   $$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$
   Where Attack Vector ($\text{AV}$), Attack Complexity ($\text{AC}$), Privileges Required ($\text{PR}$), and User Interaction ($\text{UI}$) are metric coefficients.

#### Severity Ranks:
- **`CRITICAL`**: Score $\ge 9.0$
- **`HIGH`**: Score $7.0 - 8.9$
- **`MEDIUM`**: Score $4.0 - 6.9$
- **`LOW`**: Score $< 4.0$

---

### Human-Readable Terminal & JSON Report Renderers

#### 1. `render_human_readable(scan_meta, summary, host_info, package_manager)`
Outputs terminal UI box layout displaying:
- Target name, type, OS name, package manager.
- Total packages scanned and vulnerability severity counts.
- Critical & High findings breakdown with `Package`, `Installed`, `Fixed`, `Severity`, `Ecosystem`, and `Match Reason`.
- Execution timing label with `(cached)` tag when loaded from cache.

#### 2. `render_json_report(scan_meta, summary)`
Outputs machine-readable JSON:

```json
{
  "scan": {
    "id": "scan-20260815-001",
    "started_at": "2026-08-15T15:51:46Z",
    "duration": 0.05,
    "target": "application",
    "type": "app",
    "scan_types": [
      "application"
    ]
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
      "status": "affected",
      "ecosystem": "PyPI",
      "match": {
        "ecosystem": "PyPI",
        "range": {
          "introduced": "0",
          "fixed": "2.32.4"
        },
        "installed_version": "2.31.0",
        "comparator": "semver",
        "result": "affected"
      },
      "match_reason": "Installed 2.31.0 < fixed 2.32.4 in PyPI"
    }
  ]
}
```

---

## 7. CLI Controller (`scanner/cli.py`) & Commands

### CLI Command Reference Table

| Command | Aliases | Target Domain Scanned | Description |
| :--- | :--- | :--- | :--- |
| **`sentryops scan host`** | `host` | **Linux OS Packages** | Scans system packages via `dpkg` (Debian/Ubuntu) or `rpm` (RHEL/Fedora/CentOS). |
| **`sentryops scan app`** | `dependencies`, `application` | **Application Dependencies** | Scans application manifests (`requirements.txt`, `package.json`). |
| **`sentryops scan container`** | `docker` | **Container Images** | Scans base images specified in `Dockerfile` manifests. |
| **`sentryops scan all`** | `all` *(Default)* | **All 3 Domains** | Unified multi-domain scan across Host, Application, and Container targets. |

### Output Flags

- `--output text` / `-o text`: Terminal box output.
- `--output json` / `-o json`: JSON stdout output.
- `--output <path.json>` / `-o report.json`: Writes JSON report to file.
- `--format text|json` / `-f text|json`: Explicit output format option.

---

## 8. Automated Regression Test Suite (`tests/test_engine.py`)

The automated regression suite runs 10 test cases in 0.01s:

```bash
python3 -m unittest tests/test_engine.py
```

### Verified Test Cases:
1. `test_01_firefox_esr_no_cross_release_leak`: Verifies `firefox-esr` on Debian 13 does not leak Debian 11 fix (`117.0.5938.132-1~deb11u1`).
2. `test_02_jq_clean_debian13_fix`: Verifies `jq 1.7.1-6+deb13u2` matches fixed version `1.7.1-6+deb13u3`.
3. `test_03_perl_no_subpackage_leak`: Verifies `perl 5.40.1-6` does not inherit sub-package ranges (`libio-compress-perl 2.220-1`).
4. `test_04_7zip_no_debian12_leak`: Verifies `7zip` does not leak Debian 12 fix (`22.01+really26.02...deb12u1`).
5. `test_05_xwayland_priority_fixed_range_patched`: Verifies `xwayland 2:24.1.6-1` evaluates fixed version `2:21.1.16-1.3+deb13u2` as patched (`is_affected = False`).
6. `test_06_curl_open_range`: Verifies `curl 8.11.1-1` open range evaluation `[0, ∞)`.
7. `test_07_vim_structured_match`: Verifies `vim` structured `match` dict generation (`comparator: dpkg`).
8. `test_08_python3_13_version_comparison`: Verifies `dpkg` version comparison (`3.13.1-1 < 3.13.1-2`).
9. `test_09_openssl_fixed_range_check`: Verifies `openssl 3.0.13-1` fixed range comparison (`3.0.14-1`).
10. `test_10_libxml2_unimportant_urgency_filter`: Verifies `urgency == "unimportant"` filtering.

---

## 9. Interview & Audit Cheat-Sheet

If asked about SentryOps during an architecture review or interview, use these concise explanations:

Q1: **How does SentryOps prevent cross-release false positives (e.g. Debian 11 fixes showing on Debian 13)?**
> *"SentryOps inspects OSV `affected` entries and strictly filters for `package.ecosystem == target_ecosystem` (e.g. `Debian:13`). Advisories for other releases like `Debian:11` or `Debian:12` are completely ignored."*

Q2: **Why do standard semver libraries fail for Linux OS packages, and how does SentryOps solve it?**
> *"Debian versions use epochs (`2:`), revisions (`-7`), and backport suffixes (`~deb13u2`). Standard semver parsers fail on these strings. SentryOps delegates version comparison to system `dpkg --compare-versions` via subprocess."*

Q3: **What happens if a package has multiple OSV range entries (e.g. a fixed range and an open range)?**
> *"SentryOps implements a Priority Range Evaluator. It checks ranges containing `fixed` versions first. If the installed version is `>=` all fixed versions for that package in the target ecosystem, the package is recognized as patched and not flagged as vulnerable."*

Q4: **How does SentryOps achieve high scanning speed across 1,800+ system packages?**
> *"SentryOps uses OSV's batch endpoint (`/v1/querybatch`) to send up to 1,000 package queries per HTTP POST request. It also maintains a local JSON disk cache (`.sentryops_cache.json`) under `{ecosystem}:{name}=={version}` keys for sub-second repeat scans."*

Q5: **How are vulnerability severities classified?**
> *"SentryOps implements the official FIRST.org CVSS v3.1 Base Score formula, calculating exact numerical scores from 0.0 to 10.0 based on Confidentiality, Integrity, Availability, Attack Vector, and Privileges Required metrics."*
