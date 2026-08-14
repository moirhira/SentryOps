"""
Formatter module for SentryOps vulnerability scanner.
Supports Human-Readable terminal output and Machine-Readable JSON output.
"""

import json
from datetime import datetime
from typing import Any


import math


def calculate_cvss_score(severity_str: str) -> float | None:
    """Parse CVSS v3.x vector from severity string and compute base score."""
    if not severity_str or not isinstance(severity_str, str):
        return None

    if "AV:" in severity_str:
        parts = severity_str.split()
        vector_part = None
        for p in parts:
            if "AV:" in p:
                vector_part = p
                break

        if not vector_part:
            vector_part = severity_str

        metrics = {}
        for item in vector_part.split("/"):
            if ":" in item:
                k, v = item.split(":", 1)
                metrics[k.upper()] = v.upper()

        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        ui_map = {"N": 0.85, "R": 0.62}
        c_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        i_map = {"H": 0.56, "L": 0.22, "N": 0.0}
        a_map = {"H": 0.56, "L": 0.22, "N": 0.0}

        s = metrics.get("S", "U")
        pr = metrics.get("PR", "N")

        if s == "U":
            pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
        else:
            pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}

        av = av_map.get(metrics.get("AV", "N"), 0.85)
        ac = ac_map.get(metrics.get("AC", "L"), 0.77)
        pr_val = pr_map.get(pr, 0.85)
        ui = ui_map.get(metrics.get("UI", "N"), 0.85)

        c = c_map.get(metrics.get("C", "N"), 0.0)
        i = i_map.get(metrics.get("I", "N"), 0.0)
        a = a_map.get(metrics.get("A", "N"), 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        if impact <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr_val * ui

        if s == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

        return math.ceil(score * 10.0) / 10.0

    return None


def classify_severity(vuln: dict[str, Any]) -> str:
    """Classify vulnerability severity into CRITICAL, HIGH, MEDIUM, LOW."""
    sev_str = str(vuln.get("severity", ""))
    
    cvss_score = calculate_cvss_score(sev_str)
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    sev_upper = sev_str.upper()
    if "CRITICAL" in sev_upper:
        return "CRITICAL"
    if "HIGH" in sev_upper:
        return "HIGH"
    if "MEDIUM" in sev_upper or "MODERATE" in sev_upper:
        return "MEDIUM"
    if "LOW" in sev_upper or "UNIMPORTANT" in sev_upper or "END-OF-LIFE" in sev_upper:
        return "LOW"

    return "MEDIUM"


def extract_package_info(pkg_key: str) -> tuple[str, str]:
    """Parse package name and installed version from 'name==version' string."""
    if "==" in pkg_key:
        name, version = pkg_key.split("==", 1)
        return name, version
    return pkg_key, "unknown"


def build_scan_summary(
    scanned_counts: dict[str, int],
    findings_by_category: dict[str, dict[str, list[dict]]]
) -> dict[str, Any]:
    """Build summary counts (total packages, total vulnerabilities, breakdown by severity)."""
    total_packages = sum(scanned_counts.values())
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_vulns = 0

    flattened_findings = []

    for category, category_findings in findings_by_category.items():
        for pkg_key, vulns in category_findings.items():
            pkg_name, installed_version = extract_package_info(pkg_key)
            for v in vulns:
                sev = classify_severity(v)
                severity_counts[sev] += 1
                total_vulns += 1
                flattened_findings.append({
                    "cve_id": v.get("id", "UNKNOWN"),
                    "package": pkg_name,
                    "installed": installed_version,
                    "fixed": v.get("fixed") or "None",
                    "severity": sev,
                    "ecosystem": v.get("ecosystem", "unknown"),
                    "match_reason": v.get("match_reason", "Matched advisory"),
                    "summary": v.get("summary", ""),
                    "category": category,
                })

    return {
        "packages": total_packages,
        "vulnerabilities": total_vulns,
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "findings_list": flattened_findings,
    }


def render_human_readable(
    scan_meta: dict[str, Any],
    summary: dict[str, Any],
    host_info: Any,
    package_manager: str = "dpkg"
) -> str:
    """Render human-readable text output for terminal operator."""
    lines = []
    lines.append("SentryOps Security Scanner")
    lines.append("───────────────────────────")
    lines.append("")

    target_name = scan_meta.get("target_name", "localhost")
    target_type = scan_meta.get("target_type", "Linux Host")
    os_name = f"{host_info.os_name or 'Linux'} {host_info.version or ''}".strip() if host_info else "Linux"

    lines.append(f"Target:   {target_name}")
    lines.append(f"Type:     {target_type}")
    lines.append(f"OS:       {os_name}")
    lines.append(f"Manager:  {package_manager}")
    lines.append("")
    lines.append(f"Packages scanned: {summary['packages']}")
    lines.append("")
    lines.append("Vulnerabilities")
    lines.append("───────────────────────────")
    lines.append("")
    lines.append(f"CRITICAL  {summary['critical']}")
    lines.append(f"HIGH      {summary['high']}")
    lines.append(f"MEDIUM    {summary['medium']}")
    lines.append(f"LOW       {summary['low']}")
    lines.append("")

    # Display CRITICAL & HIGH FINDINGS
    critical_or_high = [f for f in summary["findings_list"] if f["severity"] in ("CRITICAL", "HIGH")]

    if critical_or_high:
        lines.append("CRITICAL FINDINGS" if not any(f["severity"] == "HIGH" for f in critical_or_high) else "CRITICAL & HIGH FINDINGS")
        lines.append("")
        for f in critical_or_high:
            lines.append(f"{f['cve_id']}")
            lines.append(f"Package:      {f['package']}")
            lines.append(f"Installed:    {f['installed']}")
            lines.append(f"Fixed:        {f['fixed']}")
            lines.append(f"Severity:     {f['severity']}")
            lines.append(f"Ecosystem:    {f['ecosystem']}")
            lines.append(f"Match Reason: {f['match_reason']}")
            lines.append("")

    lines.append("───────────────────────────")
    duration = scan_meta.get("duration", 0.0)
    cache_tag = " (cached)" if scan_meta.get("is_cached") else ""
    lines.append(f"Scan completed in {duration:.1f}s{cache_tag}")

    return "\n".join(lines)


def render_json_report(
    scan_meta: dict[str, Any],
    summary: dict[str, Any]
) -> str:
    """Render machine-readable JSON output."""
    report = {
        "scan": {
            "id": scan_meta.get("id", f"scan-{datetime.now().strftime('%Y%m%d')}-001"),
            "started_at": scan_meta.get("started_at", datetime.now().isoformat()),
            "duration": scan_meta.get("duration", 0.0),
            "target": scan_meta.get("target_name", "localhost"),
            "type": scan_meta.get("target_type_short", "host")
        },
        "summary": {
            "packages": summary["packages"],
            "vulnerabilities": summary["vulnerabilities"],
            "critical": summary["critical"],
            "high": summary["high"],
            "medium": summary["medium"],
            "low": summary["low"]
        },
        "findings": [
            {
                "cve_id": f["cve_id"],
                "package": f["package"],
                "installed": f["installed"],
                "fixed": f["fixed"],
                "severity": f["severity"],
                "ecosystem": f["ecosystem"],
                "match_reason": f["match_reason"],
            }
            for f in summary["findings_list"]
        ]
    }
    return json.dumps(report, indent=2)
