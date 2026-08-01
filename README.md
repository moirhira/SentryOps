# Infrastructure Vulnerability Scanner — Project Spec

## Overview

A lightweight DevSecOps tool that periodically scans an environment's installed
packages/dependencies, cross-references them against known CVE databases, and
reports findings — with metrics exported to Prometheus/Grafana for trend
visibility over time.

**Goal:** Build legitimate, hands-on experience with vulnerability management,
CVE tooling, and AWS deployment — directly relevant to DevSecOps / AIOps /
SRE roles.

---

## Problem Statement

Most teams don't have visibility into which of their dependencies carry known
vulnerabilities until a scan is run manually or a breach happens. This project
automates that check on a recurring schedule (daily / weekly / monthly) and
tracks how exposure changes over time — especially for packages tied to
critical services.

---

## Core Features (MVP)

- [ ] Parse installed packages from common manifest formats:
  - `requirements.txt` (Python)
  - `package.json` / `package-lock.json` (Node)
  - `Dockerfile` base images
  - `dpkg`/`apt` package lists (for full-system scans)
- [ ] Query CVE data for each package/version found
  - Primary source: [OSV.dev API](https://osv.dev) (free, no API key, strong
    open-source coverage)
  - Secondary/optional: [NVD API](https://nvd.nist.gov/developers) (broader
    but requires an API key for reasonable rate limits)
- [ ] Classify findings by severity (Critical / High / Medium / Low) using
  CVSS scores
- [ ] Flag packages tied to a user-defined list of "critical services"
- [ ] Store scan results (SQLite for MVP, Postgres if scaling) to enable
  historical comparison ("3 new CVEs since last scan")
- [ ] Generate a report per scan (JSON + simple HTML summary)
- [ ] Run on a schedule (cron, or AWS EventBridge if deployed as Lambda)

---

## Stretch Features (post-MVP)

- [ ] Export scan metrics to Prometheus (`cve_count_critical`,
  `cve_count_high`, `cve_count_new`, etc.) and build a Grafana dashboard
  showing exposure trends over time
- [ ] Wazuh integration/comparison:
  - Deploy Wazuh in a lab environment (official Docker Compose stack)
  - Either feed scanner output into Wazuh as custom alerts, or
  - Write a short comparison doc: what Wazuh's vulnerability-detection
    module covers out of the box vs. what this scanner adds
- [ ] FinOps module: tag AWS resources and report estimated cost per service
  alongside the security report (only pursued if time allows — cloud cost +
  cloud security in one view)

---

## Architecture (MVP)

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐
│  Package Parser  │ ──▶ │  CVE Lookup  │ ──▶ │  Report Gen   │
│ (reads manifests)│     │ (OSV.dev API)│     │ (JSON + HTML) │
└─────────────────┘     └──────────────┘     └───────┬───────┘
                                                       │
                                              ┌────────▼────────┐
                                              │  SQLite Storage  │
                                              │ (scan history)   │
                                              └────────┬────────┘
                                                       │
                                          ┌────────────▼────────────┐
                                          │ Prometheus metrics /    │
                                          │ Grafana dashboard       │
                                          │ (stretch)               │
                                          └─────────────────────────┘
```

**Deployment target:** Dockerized, run on a small AWS EC2 instance or as a
scheduled AWS Lambda (EventBridge trigger).

---

## Tech Stack

| Component        | Choice                          | Why |
|-------------------|----------------------------------|-----|
| Language          | Python 3.11+                     | Best CVE/package-parsing ecosystem, fast to prototype |
| CVE data          | OSV.dev API                      | Free, no key required, good OSS coverage |
| Storage           | SQLite (MVP) → Postgres (later)  | Zero-setup for MVP, easy migration path |
| Containerization  | Docker                           | Already proficient (Inception, BOMA, NodeTalk) |
| Scheduling        | cron / AWS EventBridge           | Simple, standard |
| Metrics/dashboard | Prometheus + Grafana             | Direct reuse of existing NodeTalk/BOMA experience |
| Deployment        | AWS EC2 or Lambda                | Gives legitimate, real AWS hands-on time |

---

## Build Plan

| Phase | Timeframe | Deliverable |
|-------|-----------|-------------|
| 1     | Week 1–2  | Core scanner: package parsing + CVE lookup + JSON report (demo-able) |
| 2     | Week 3    | Prometheus metrics export + Grafana dashboard |
| 3     | Week 4    | Wazuh lab deployment + comparison writeup |
| 4     | Optional  | FinOps module, Lambda deployment, full scheduling automation |

---

## Success Criteria

- Scanner correctly identifies known CVEs in a test project's dependencies
  (validate against a repo with known vulnerable packages)
- Historical comparison works: running the scan twice shows delta correctly
- Dashboard visibly tracks severity counts over at least 2–3 scan cycles
- Wazuh comparison doc clearly explains overlap/differences (even without
  full integration)

---

## Why This Project

- Produces **honest, hands-on AWS experience** (deployment, not just theory)
- Reuses and extends existing observability skills (Prometheus/Grafana from
  NodeTalk and BOMA)
- Gives real exposure to Wazuh — a tool frequently required/expected in
  security-focused DevOps roles
- Directly strengthens the STMicroelectronics AIOps application by adding a
  pattern-detection/monitoring angle on top of infrastructure data
- Results in a genuine "DevSecOps" project entry for resume/portfolio, with
  no fabricated claims
