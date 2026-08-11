import argparse
import time
from datetime import datetime, timezone
from pathlib import Path

from scanner.application import scan_application
from scanner.container import scan_container
from scanner.formatter import (
    build_scan_summary,
    render_human_readable,
    render_json_report,
)
from scanner.host import get_host_info, scan_host
from scanner.osv import check_dependencies, filter_actionable_vulns


def run_scan(
    target: str,
    base_dir: Path = Path("."),
    output_option: str = "text",
    format_option: str | None = None,
) -> None:
    start_time = time.time()
    started_at_iso = datetime.now(timezone.utc).isoformat()

    host_info = None
    try:
        host_info = get_host_info()
    except Exception:
        pass

    findings_by_category = {}
    scanned_counts = {}

    target_clean = target.lower()

    # Determine target metadata
    if target_clean == "host":
        target_name = "localhost"
        target_type = "Linux Host"
        target_type_short = "host"
    elif target_clean in ("dependencies", "app", "application"):
        target_name = "application"
        target_type = "Application Dependencies"
        target_type_short = "app"
    elif target_clean in ("container", "docker"):
        target_name = "container"
        target_type = "Container Base Images"
        target_type_short = "container"
    else:
        target_name = "localhost"
        target_type = "Full Infrastructure & App"
        target_type_short = "all"

    # Determine Package Manager
    pkg_manager = "unknown"
    if host_info and host_info.os_id:
        if host_info.os_id in ("ubuntu", "debian", "linuxmint", "pop", "raspbian", "kali"):
            pkg_manager = "dpkg"
        elif host_info.os_id in ("rhel", "fedora", "centos", "rocky", "almalinux", "amzn"):
            pkg_manager = "rpm"
        else:
            pkg_manager = host_info.os_id

    # 1. Host Domain
    if target_clean in ("host", "all"):
        if host_info:
            try:
                host_deps = scan_host()
                host_raw = check_dependencies(host_deps, os_id=host_info.os_id, os_version=host_info.version)
                findings_by_category["host"] = filter_actionable_vulns(host_raw)
                scanned_counts["host"] = len(host_deps)
            except Exception:
                findings_by_category["host"] = {}
                scanned_counts["host"] = 0
        else:
            findings_by_category["host"] = {}
            scanned_counts["host"] = 0

    # 2. Application Domain
    if target_clean in ("dependencies", "app", "application", "all"):
        app_deps = scan_application(base_dir)
        app_raw = check_dependencies(app_deps)
        findings_by_category["application"] = filter_actionable_vulns(app_raw)
        scanned_counts["application"] = len(app_deps)

    # 3. Container Domain
    if target_clean in ("container", "docker", "all"):
        container_deps = scan_container(base_dir)
        container_raw = check_dependencies(container_deps)
        findings_by_category["container"] = filter_actionable_vulns(container_raw)
        scanned_counts["container"] = len(container_deps)

    duration = round(time.time() - start_time, 2)

    scan_meta = {
        "id": f"scan-{datetime.now().strftime('%Y%m%d')}-001",
        "started_at": started_at_iso,
        "duration": duration,
        "is_cached": duration < 1.0,
        "target_name": target_name,
        "target_type": target_type,
        "target_type_short": target_type_short,
    }

    summary = build_scan_summary(scanned_counts, findings_by_category)

    # Determine requested format
    out_lower = output_option.lower()
    fmt_lower = (format_option or "").lower()

    is_json = out_lower == "json" or fmt_lower == "json"
    is_file = out_lower.endswith(".json") and out_lower != "json"

    if is_json:
        json_output = render_json_report(scan_meta, summary)
        print(json_output)
    elif is_file:
        file_path = Path(output_option)
        json_output = render_json_report(scan_meta, summary)
        try:
            file_path.write_text(json_output)
        except OSError as e:
            print(f"Failed to write report to {file_path}: {e}")

        # Also print human readable terminal output
        print(render_human_readable(scan_meta, summary, host_info, pkg_manager))
        print(f"\nReport saved to: {file_path.resolve()}")
    else:
        # Default human readable output
        print(render_human_readable(scan_meta, summary, host_info, pkg_manager))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentryops",
        description="SentryOps Infrastructure & Application Vulnerability Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["host", "dependencies", "app", "application", "container", "docker", "all"],
        help="Target domain to scan: host, dependencies, container, or all (default: all)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="text",
        help="Output format ('text', 'json') or path to JSON report file (default: text)",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        type=str,
        default=None,
        choices=["text", "json"],
        help="Explicit output format: 'text' or 'json'",
    )

    args = parser.parse_args()

    if args.command == "scan" or args.command is None:
        target = getattr(args, "target", "all") or "all"
        output = getattr(args, "output", "text")
        fmt = getattr(args, "format", None)
        run_scan(target, output_option=output, format_option=fmt)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
