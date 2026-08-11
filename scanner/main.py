import json
from datetime import datetime, timezone
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from scanner.host import get_host_info, scan_host
from scanner.application import scan_application
from scanner.container import scan_container
from scanner.osv import check_dependencies, filter_actionable_vulns


def save_report(
    host_info,
    scanned_counts: dict,
    findings_by_category: dict,
    output_path: Path = Path("report.json")
) -> None:
    total_actionable_cves = sum(
        sum(len(v) for v in category_findings.values())
        for category_findings in findings_by_category.values()
    )

    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": {
            "os_name": host_info.os_name,
            "os_id": host_info.os_id,
            "version": host_info.version,
            "architecture": host_info.architecture,
        },
        "summary": {
            "total_packages_scanned": sum(scanned_counts.values()),
            "packages_scanned_by_category": scanned_counts,
            "total_actionable_cves": total_actionable_cves,
        },
        "findings": findings_by_category
    }

    try:
        output_path.write_text(json.dumps(report_data, indent=2))
        print(f"\nReport saved to: {output_path.resolve()}")
    except OSError as e:
        print(f"Failed to write report to {output_path}: {e}")


if __name__ == "__main__":
    print("==================================================")
    print("        SentryOps Vulnerability Scanner           ")
    print("==================================================")

    # 1. Host Domain (dpkg / rpm)
    host = get_host_info()
    print(f"\n[Host Scan] OS: {host.os_name} ({host.architecture}) | ID: {host.os_id}, Version: {host.version}")
    host_deps = scan_host()
    print(f"  -> Discovered {len(host_deps)} system packages ({host.os_id}).")

    # 2. Application Domain (requirements.txt, package.json)
    print("\n[Application Scan] Manifests (requirements.txt, package.json)...")
    app_deps = scan_application(Path("."))
    print(f"  -> Discovered {len(app_deps)} application dependencies.")

    # 3. Container Domain (Dockerfile)
    print("\n[Container Scan] Base images (Dockerfile)...")
    container_deps = scan_container(Path("."))
    print(f"  -> Discovered {len(container_deps)} container base image dependencies.")

    # Run CVE Checks
    print("\n--------------------------------------------------")
    print("Querying OSV Database & Hydrating Metadata...")
    print("--------------------------------------------------")

    host_raw = check_dependencies(host_deps, os_id=host.os_id, os_version=host.version)
    host_findings = filter_actionable_vulns(host_raw)

    app_raw = check_dependencies(app_deps)
    app_findings = filter_actionable_vulns(app_raw)

    container_raw = check_dependencies(container_deps)
    container_findings = filter_actionable_vulns(container_raw)

    findings_by_category = {
        "host": host_findings,
        "application": app_findings,
        "container": container_findings,
    }

    scanned_counts = {
        "host": len(host_deps),
        "application": len(app_deps),
        "container": len(container_deps),
    }

    print("\n=== Scan Results by Target Domain ===")
    for domain, findings in findings_by_category.items():
        print(f"\n[{domain.upper()}] Actionable Findings: {len(findings)} package(s)")
        if findings:
            for pkg, vulns in findings.items():
                print(f"  {pkg}:")
                for v in vulns:
                    print(f"    - {v['id']} [{v['severity']}] - {v['summary']}")
        else:
            print("  No actionable vulnerabilities found.")

    save_report(host, scanned_counts, findings_by_category, Path("report.json"))
