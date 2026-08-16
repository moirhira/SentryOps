import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from scanner.application import scan_application
from scanner.container import scan_container
from scanner.db import compare_scans, generate_scan_id, get_scan, list_scans, save_scan
from scanner.formatter import (
    build_scan_summary,
    render_human_readable,
    render_json_report,
)
from scanner.host import get_host_info, scan_host
from scanner.osv import check_dependencies, filter_actionable_vulns

# ─── ANSI colour helpers ──────────────────────────────────────────────────────
_SEV_COLOUR = {
    "CRITICAL": "\033[1;31m",   # bold red
    "HIGH":     "\033[0;31m",   # red
    "MEDIUM":   "\033[0;33m",   # yellow
    "LOW":      "\033[0;36m",   # cyan
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_GREEN = "\033[0;32m"


def _sev(label: str | None) -> str:
    colour = _SEV_COLOUR.get(label or "", "")
    return f"{colour}{label or 'N/A'}{_RESET}"


def _delta_str(d: int) -> str:
    if d > 0:
        return f"\033[0;31m+{d}{_RESET}"
    if d < 0:
        return f"{_GREEN}{d}{_RESET}"
    return f"{_DIM}  0{_RESET}"


def _div(char: str = "─", width: int = 60) -> str:
    return char * width


# ─────────────────────────────────────────────────────────────────────────────
# SCAN
# ─────────────────────────────────────────────────────────────────────────────

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

    # Determine package manager
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
    scan_types = list(scanned_counts.keys())

    scan_meta = {
        "id": generate_scan_id(),
        "started_at": started_at_iso,
        "duration": duration,
        "is_cached": duration < 1.0,
        "target_name": target_name,
        "target_type": target_type,
        "target_type_short": target_type_short,
        "scan_types": scan_types,
    }

    summary = build_scan_summary(scanned_counts, findings_by_category)

    # Persist to SQLite
    try:
        save_scan(
            scan_meta=scan_meta,
            host_info=host_info,
            pkg_manager=pkg_manager,
            findings_by_category=findings_by_category,
        )
    except Exception as e:
        print(f"[warning] Could not save scan to database: {e}")

    # Output
    out_lower = output_option.lower()
    fmt_lower = (format_option or "").lower()
    is_json = out_lower == "json" or fmt_lower == "json"
    is_file = out_lower.endswith(".json") and out_lower != "json"

    if is_json:
        print(render_json_report(scan_meta, summary))
    elif is_file:
        file_path = Path(output_option)
        json_output = render_json_report(scan_meta, summary)
        try:
            file_path.write_text(json_output)
        except OSError as e:
            print(f"Failed to write report to {file_path}: {e}")
        print(render_human_readable(scan_meta, summary, host_info, pkg_manager))
        print(f"\nReport saved to: {file_path.resolve()}")
    else:
        print(render_human_readable(scan_meta, summary, host_info, pkg_manager))


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY — list
# ─────────────────────────────────────────────────────────────────────────────

def run_history(limit: int = 10) -> None:
    """Print a table of the N most recent scans."""
    scans = list_scans(limit=limit)
    if not scans:
        print("No scan history found. Run 'sentryops scan host' to get started.")
        return

    col_id       = 32
    col_started  = 20
    col_target   = 16
    col_os       = 26
    col_dur      =  7

    header = (
        f"{_BOLD}{'Scan ID':<{col_id}} {'Started':<{col_started}} "
        f"{'Target':<{col_target}} {'OS':<{col_os}} {'Dur':>{col_dur}}  "
        f"Findings (C / H / M / L){_RESET}"
    )
    print()
    print(header)
    print(_div(width=col_id + col_started + col_target + col_os + col_dur + 26))

    for s in scans:
        c  = s.get("critical") or 0
        h  = s.get("high")     or 0
        m  = s.get("medium")   or 0
        lo = s.get("low")      or 0
        findings_str = (
            f"{_SEV_COLOUR['CRITICAL']}{c:>3}C{_RESET} / "
            f"{_SEV_COLOUR['HIGH']}{h:>4}H{_RESET} / "
            f"{_SEV_COLOUR['MEDIUM']}{m:>4}M{_RESET} / "
            f"{_SEV_COLOUR['LOW']}{lo:>4}L{_RESET}"
        )
        dur  = f"{s['duration']:.1f}s" if s.get("duration") is not None else "N/A"
        os_s = (s.get("os") or "N/A")[:col_os]
        tgt  = (s.get("target") or "N/A")[:col_target]
        ts   = (s["started_at"] or "")[:19].replace("T", " ")
        print(
            f"{s['id']:<{col_id}} {ts:<{col_started}} "
            f"{tgt:<{col_target}} {os_s:<{col_os}} {dur:>{col_dur}}  {findings_str}"
        )
    print()


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY — show <scan-id>
# ─────────────────────────────────────────────────────────────────────────────

def run_history_show(scan_id: str) -> None:
    """Print detailed metadata and finding counts for a single scan."""
    result = get_scan(scan_id)
    if result is None:
        print(f"Scan not found: {scan_id}")
        return

    s = result["scan"]
    findings = result["findings"]

    scan_types = []
    try:
        scan_types = json.loads(s.get("scan_types") or "[]")
    except Exception:
        pass

    # Severity breakdown
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_pkgs: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity") or "LOW"
        if sev in sev_counts:
            sev_counts[sev] += 1
        pkg = f.get("package_name") or "unknown"
        top_pkgs[pkg] = top_pkgs.get(pkg, 0) + 1

    total = sum(sev_counts.values())
    started = (s.get("started_at") or "")[:19].replace("T", " ")

    print()
    print(f"{_BOLD}Scan Details{_RESET}")
    print(_div())
    print(f"{'ID':<18} {s['id']}")
    print(f"{'Started':<18} {started} UTC")
    print(f"{'Target':<18} {s.get('target','N/A')} ({s.get('target_type','N/A')})")
    print(f"{'OS':<18} {s.get('os') or 'N/A'}")
    print(f"{'Duration':<18} {s['duration']:.2f}s" if s.get("duration") is not None else f"{'Duration':<18} N/A")
    print(f"{'Status':<18} {s.get('status','N/A')}")
    print(f"{'Scanner':<18} v{s.get('scanner_version','?')}")
    print(f"{'Scan types':<18} {', '.join(scan_types) or 'N/A'}")

    print()
    print(f"{_BOLD}Findings Summary{_RESET}")
    print(_div())
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bar = "█" * min(sev_counts[sev], 40)
        print(f"  {_sev(sev):<22} {sev_counts[sev]:>5}  {_DIM}{bar}{_RESET}")
    print(f"  {'─'*20}")
    print(f"  {'TOTAL':<14} {total:>5}")

    print()
    print(f"{_BOLD}Top Packages by Finding Count{_RESET}")
    print(_div())
    for pkg, cnt in sorted(top_pkgs.items(), key=lambda x: -x[1])[:10]:
        bar = "▪" * min(cnt, 30)
        print(f"  {pkg:<24} {cnt:>4}  {_DIM}{bar}{_RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY — findings <scan-id>
# ─────────────────────────────────────────────────────────────────────────────

def run_history_findings(scan_id: str, severity: str | None = None) -> None:
    """Print every finding for a scan, grouped by severity."""
    result = get_scan(scan_id)
    if result is None:
        print(f"Scan not found: {scan_id}")
        return

    findings = result["findings"]
    if severity:
        findings = [f for f in findings if (f.get("severity") or "").upper() == severity.upper()]

    if not findings:
        print("No findings match the given criteria.")
        return

    print()
    print(f"{_BOLD}Findings — {scan_id}{_RESET}")
    print(_div())

    current_sev = None
    for f in findings:
        sev = f.get("severity") or "UNKNOWN"
        if sev != current_sev:
            current_sev = sev
            print(f"\n  {_BOLD}{_sev(sev)}{_RESET}")
            print(f"  {'Package':<28} {'Vulnerability ID':<32} {'Installed':<28} {'Fixed'}")
            print(f"  {'─'*24} {'─'*30} {'─'*26} {'─'*20}")

        pkg     = (f.get("package_name") or "N/A")[:27]
        vuln_id = (f.get("vulnerability_id") or "N/A")[:31]
        inst    = (f.get("installed_version") or "N/A")[:27]
        fixed   = f.get("fixed_version") or f"{_DIM}no fix{_RESET}"
        print(f"  {pkg:<28} {vuln_id:<32} {inst:<28} {fixed}")

    print()
    print(f"{_DIM}Total findings shown: {len(findings)}{_RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY — compare <old-scan-id> <new-scan-id>
# ─────────────────────────────────────────────────────────────────────────────

def run_history_compare(old_id: str, new_id: str) -> None:
    """Print a side-by-side diff between two scans."""
    try:
        result = compare_scans(old_id, new_id)
    except ValueError as e:
        print(f"Error: {e}")
        return

    old_s = result["old_scan"]
    new_s = result["new_scan"]
    delta = result["severity_delta"]
    new_v = result["new_vulns"]
    res_v = result["resolved_vulns"]

    old_ts = (old_s.get("started_at") or "")[:19].replace("T", " ")
    new_ts = (new_s.get("started_at") or "")[:19].replace("T", " ")

    print()
    print(f"{_BOLD}Scan Comparison{_RESET}")
    print(_div())
    print(f"  {'Previous':<12} {old_s['id']}  {_DIM}({old_ts} UTC){_RESET}")
    print(f"  {'Current':<12} {new_s['id']}  {_DIM}({new_ts} UTC){_RESET}")

    # Security posture table
    print()
    print(f"{_BOLD}Security Posture{_RESET}")
    print(_div())
    print(f"  {'Severity':<12} {'Before':>8} {'After':>8} {'Change':>10}")
    print(f"  {'─'*10} {'─'*8} {'─'*8} {'─'*10}")
    total_old = 0
    total_new = 0
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        d = delta[sev]
        total_old += d["old"]
        total_new += d["new"]
        print(
            f"  {_sev(sev):<22} {d['old']:>8} {d['new']:>8} {_delta_str(d['delta']):>20}"
        )
    net = total_new - total_old
    print(f"  {'─'*10} {'─'*8} {'─'*8} {'─'*10}")
    print(
        f"  {'TOTAL':<12} {total_old:>8} {total_new:>8} {_delta_str(net):>20}"
    )
    print(f"\n  {_DIM}Unchanged: {result['persisted_count']} findings carried over{_RESET}")

    # New vulnerabilities
    print()
    print(f"{_BOLD}New Vulnerabilities  (+{len(new_v)}){_RESET}")
    print(_div())
    if new_v:
        print(f"  {'Severity':<12} {'Package':<24} {'Vulnerability ID':<32} {'Fixed'}")
        print(f"  {'─'*10} {'─'*22} {'─'*30} {'─'*18}")
        for v in new_v:
            sev_s  = _sev(v.get("severity"))
            pkg_s  = (v.get("package") or "N/A")[:23]
            vid_s  = (v.get("vulnerability_id") or "N/A")[:31]
            fix_s  = v.get("fixed_version") or f"{_DIM}no fix{_RESET}"
            print(f"  {sev_s:<22} {pkg_s:<24} {vid_s:<32} {fix_s}")
    else:
        print(f"  {_GREEN}No new vulnerabilities introduced.{_RESET}")

    # Resolved vulnerabilities
    print()
    print(f"{_BOLD}Resolved Vulnerabilities  (-{len(res_v)}){_RESET}")
    print(_div())
    if res_v:
        print(f"  {'Severity':<12} {'Package':<24} {'Vulnerability ID':<32} {'Was Fixed'}")
        print(f"  {'─'*10} {'─'*22} {'─'*30} {'─'*18}")
        for v in res_v:
            sev_s  = _sev(v.get("severity"))
            pkg_s  = (v.get("package") or "N/A")[:23]
            vid_s  = (v.get("vulnerability_id") or "N/A")[:31]
            fix_s  = v.get("fixed_version") or f"{_DIM}—{_RESET}"
            print(f"  {sev_s:<22} {pkg_s:<24} {vid_s:<32} {fix_s}")
    else:
        print(f"  {_DIM}No previously known vulnerabilities disappeared.{_RESET}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentryops",
        description="SentryOps Infrastructure & Application Vulnerability Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # ── scan ─────────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Run a vulnerability scan")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["host", "dependencies", "app", "application", "container", "docker", "all"],
        help="Domain to scan (default: all)",
    )
    scan_parser.add_argument(
        "--output", "-o", type=str, default="text",
        help="Output format ('text', 'json') or path to .json report file",
    )
    scan_parser.add_argument(
        "--format", "-f", type=str, default=None, choices=["text", "json"],
        help="Explicit output format override",
    )

    # ── history ───────────────────────────────────────────────────────────────
    history_parser = subparsers.add_parser("history", help="Browse scan history")
    history_sub = history_parser.add_subparsers(dest="history_cmd")

    # history [no subcommand] — list recent scans
    history_parser.add_argument(
        "--limit", "-n", type=int, default=10,
        help="Number of recent scans to display (default: 10)",
    )

    # history show <scan-id>
    show_p = history_sub.add_parser("show", help="Show details for a specific scan")
    show_p.add_argument("scan_id", help="Scan ID to inspect")

    # history findings <scan-id>
    findings_p = history_sub.add_parser("findings", help="List all findings for a specific scan")
    findings_p.add_argument("scan_id", help="Scan ID to list findings for")
    findings_p.add_argument(
        "--severity", "-s", type=str, default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter findings by severity",
    )

    # history compare <old-scan-id> <new-scan-id>
    compare_p = history_sub.add_parser("compare", help="Compare two scans side-by-side")
    compare_p.add_argument("old_scan_id", help="Baseline (older) scan ID")
    compare_p.add_argument("new_scan_id", help="Current (newer) scan ID")

    args = parser.parse_args()

    # ── dispatch ──────────────────────────────────────────────────────────────
    if args.command == "scan" or args.command is None:
        target = getattr(args, "target", "all") or "all"
        output = getattr(args, "output", "text")
        fmt    = getattr(args, "format", None)
        run_scan(target, output_option=output, format_option=fmt)

    elif args.command == "history":
        hcmd = getattr(args, "history_cmd", None)
        if hcmd == "show":
            run_history_show(args.scan_id)
        elif hcmd == "findings":
            run_history_findings(args.scan_id, severity=args.severity)
        elif hcmd == "compare":
            run_history_compare(args.old_scan_id, args.new_scan_id)
        else:
            run_history(limit=args.limit)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
