import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scanner.application import scan_application
from scanner.container import scan_container
from scanner.host import get_host_info, scan_host
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


def run_scan(target: str, base_dir: Path = Path("."), output_file: Path = Path("report.json")) -> None:
    print("==================================================")
    print("        SentryOps Vulnerability Scanner           ")
    print("==================================================")

    host = get_host_info()
    findings_by_category = {}
    scanned_counts = {}

    target = target.lower()

    # 1. Host Domain
    if target in ("host", "all"):
        print(f"\n[Host Scan] OS: {host.os_name} ({host.architecture}) | ID: {host.os_id}, Version: {host.version}")
        try:
            host_deps = scan_host()
            print(f"  -> Discovered {len(host_deps)} system packages ({host.os_id}).")
            host_raw = check_dependencies(host_deps, os_id=host.os_id, os_version=host.version)
            findings_by_category["host"] = filter_actionable_vulns(host_raw)
            scanned_counts["host"] = len(host_deps)
        except Exception as e:
            print(f"  -> Host scan skipped/failed: {e}")
            findings_by_category["host"] = {}
            scanned_counts["host"] = 0

    # 2. Application Domain
    if target in ("dependencies", "app", "application", "all"):
        print(f"\n[Application Scan] Manifests (requirements.txt, package.json)...")
        app_deps = scan_application(base_dir)
        print(f"  -> Discovered {len(app_deps)} application dependencies.")
        app_raw = check_dependencies(app_deps)
        findings_by_category["application"] = filter_actionable_vulns(app_raw)
        scanned_counts["application"] = len(app_deps)

    # 3. Container Domain
    if target in ("container", "docker", "all"):
        print(f"\n[Container Scan] Base images (Dockerfile)...")
        container_deps = scan_container(base_dir)
        print(f"  -> Discovered {len(container_deps)} container base image dependencies.")
        container_raw = check_dependencies(container_deps)
        findings_by_category["container"] = filter_actionable_vulns(container_raw)
        scanned_counts["container"] = len(container_deps)

    # Summary Display
    print("\n=== Scan Results by Target Domain ===")
    for domain, findings in findings_by_category.items():
        print(f"\n[{domain.upper()}] Actionable Findings: {len(findings)} package(s)")
        if findings:
            for pkg, vulns in findings.items():
                print(f"  {pkg}:")
                for v in vulns:
                    src_info = f" ({v.get('source', '')} @ {v.get('location', '')})" if v.get("location") else ""
                    print(f"    - {v['id']} [{v['severity']}] - {v['summary']}{src_info}")
        else:
            print("  No actionable vulnerabilities found.")

    save_report(host, scanned_counts, findings_by_category, output_file)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentryops",
        description="SentryOps Infrastructure & Application Vulnerability Scanner"
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["host", "dependencies", "app", "container", "all"],
        help="Target domain to scan: host, dependencies, container, or all (default: all)"
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("report.json"),
        help="Output report JSON file path (default: report.json)"
    )

    args = parser.parse_args()

    if args.command == "scan" or args.command is None:
        target = getattr(args, "target", "all") or "all"
        output = getattr(args, "output", Path("report.json"))
        run_scan(target, output_file=output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
