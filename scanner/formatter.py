"""
Formatter module for SentryOps vulnerability scanner.
Supports Human-Readable terminal output and Machine-Readable JSON output.
"""

import json
from datetime import datetime
from typing import Any


def classify_severity(vuln: dict[str, Any]) -> str:
    """Classify vulnerability severity into CRITICAL, HIGH, MEDIUM, LOW."""
    sev_str = str(vuln.get("severity", "")).upper()
    level = vuln.get("severity_level")
    if level and level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return level

    if "CRITICAL" in sev_str:
        return "CRITICAL"
    if "HIGH" in sev_str:
        return "HIGH"
    if "MEDIUM" in sev_str or "MODERATE" in sev_str:
        return "MEDIUM"
    if "LOW" in sev_str:
        return "LOW"

    # Secondary heuristic based on CVSS metrics if present
    if "C:H/I:H/A:H" in sev_str or "C:H/I:H" in sev_str:
        return "HIGH"
    if "C:H" in sev_str or "I:H" in sev_str or "A:H" in sev_str:
        return "MEDIUM"

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
            lines.append(f"Package:   {f['package']}")
            lines.append(f"Installed: {f['installed']}")
            lines.append(f"Fixed:     {f['fixed']}")
            lines.append(f"Severity:  {f['severity']}")
            lines.append("")

    lines.append("───────────────────────────")
    duration = scan_meta.get("duration", 0.0)
    lines.append(f"Scan completed in {duration:.1f}s")

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
                "severity": f["severity"]
            }
            for f in summary["findings_list"]
        ]
    }
    return json.dumps(report, indent=2)
