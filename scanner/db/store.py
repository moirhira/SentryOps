"""
SentryOps database persistence store.

Handles inserting scan results (scans, packages, findings)
and querying scan history from SQLite.
"""

import json
from pathlib import Path
from typing import Any

from scanner.db.schema import DEFAULT_DB_PATH, get_connection, init_db

SCANNER_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# WRITE: Persist a full scan result
# ─────────────────────────────────────────────────────────────────────────────

def save_scan(
    scan_meta: dict[str, Any],
    host_info: Any,
    pkg_manager: str,
    findings_by_category: dict[str, dict[str, list[dict]]],
    db_path: Path = DEFAULT_DB_PATH,
) -> str:
    """
    Persist a complete scan result to SQLite.

    Inserts one row into `scans`, one row per discovered package into `packages`,
    and one row per finding per package into `findings`.

    Returns the scan_id stored.
    """
    init_db(db_path)

    scan_id = scan_meta["id"]
    os_label = None
    if host_info:
        os_label = f"{host_info.os_name or ''} {host_info.version or ''}".strip() or None

    with get_connection(db_path) as conn:
        # 1. Insert scan row
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (id, started_at, duration, target, target_type, scan_types, os, scanner_version, status)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                scan_meta["started_at"],
                scan_meta.get("duration"),
                scan_meta.get("target") or scan_meta.get("target_name") or "unknown",
                scan_meta.get("target_type") or scan_meta.get("type") or "unknown",
                json.dumps(scan_meta.get("scan_types", [])),
                os_label,
                SCANNER_VERSION,
                "completed",
            ),
        )

        # 2. Insert packages and findings per category
        for category, pkg_findings in findings_by_category.items():
            for pkg_key, vulns in pkg_findings.items():
                if "==" in pkg_key:
                    pkg_name, pkg_version = pkg_key.split("==", 1)
                else:
                    pkg_name, pkg_version = pkg_key, "unknown"

                # Determine ecosystem and package_manager from first vuln or category
                ecosystem = "unknown"
                source_type = category
                if vulns:
                    ecosystem = vulns[0].get("ecosystem", "unknown")
                    source_type = vulns[0].get("source", category)

                # Infer package_manager from ecosystem
                eco_upper = ecosystem.upper()
                if "DEBIAN" in eco_upper or "UBUNTU" in eco_upper:
                    package_manager = "dpkg"
                elif "RHEL" in eco_upper or "FEDORA" in eco_upper or "CENTOS" in eco_upper:
                    package_manager = "rpm"
                elif eco_upper == "PYPI":
                    package_manager = "pip"
                elif eco_upper == "NPM":
                    package_manager = "npm"
                elif eco_upper == "DOCKER":
                    package_manager = "docker"
                else:
                    package_manager = pkg_manager

                # 2a. Insert package row
                cursor = conn.execute(
                    """
                    INSERT INTO packages
                        (scan_id, name, version, ecosystem, package_manager, source_type)
                    VALUES
                        (?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, pkg_name, pkg_version, ecosystem, package_manager, source_type),
                )
                package_id = cursor.lastrowid

                # 2b. Insert one finding row per vulnerability
                for vuln in vulns:
                    match = vuln.get("match") or {}
                    match_range = match.get("range") or {}

                    conn.execute(
                        """
                        INSERT INTO findings (
                            scan_id,
                            package_id,
                            vulnerability_id,
                            installed_version,
                            fixed_version,
                            severity,
                            status,
                            ecosystem,
                            range_introduced,
                            range_fixed,
                            comparator,
                            vulnerability_source,
                            summary,
                            reference_url
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            package_id,
                            vuln.get("id") or vuln.get("cve_id") or "UNKNOWN",
                            pkg_version,
                            vuln.get("fixed") if vuln.get("fixed") != "None" else None,
                            vuln.get("severity_level") or _classify_severity_label(vuln),
                            vuln.get("status", "affected"),
                            vuln.get("ecosystem", ecosystem),
                            match_range.get("introduced"),
                            match_range.get("fixed"),
                            match.get("comparator"),
                            vuln.get("source", source_type),
                            (vuln.get("summary") or "")[:512],
                            None,   # reference_url — future extension
                        ),
                    )

    return scan_id


def _classify_severity_label(vuln: dict) -> str | None:
    """Map severity from vuln dict fields if severity_level is not directly present."""
    from scanner.formatter import classify_severity
    return classify_severity(vuln)


# ─────────────────────────────────────────────────────────────────────────────
# READ: Query scan history
# ─────────────────────────────────────────────────────────────────────────────

def list_scans(limit: int = 20, db_path: Path = DEFAULT_DB_PATH) -> list[dict]:
    """Return the N most recent scans as a list of dicts."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                s.id,
                s.started_at,
                s.duration,
                s.target,
                s.target_type,
                s.scan_types,
                s.os,
                s.scanner_version,
                s.status,
                COUNT(DISTINCT p.id) AS packages_scanned,
                COUNT(f.id)          AS total_findings,
                SUM(CASE WHEN f.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN f.severity = 'HIGH'     THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN f.severity = 'MEDIUM'   THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN f.severity = 'LOW'      THEN 1 ELSE 0 END) AS low
            FROM scans s
            LEFT JOIN packages p ON p.scan_id = s.id
            LEFT JOIN findings f ON f.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(scan_id: str, db_path: Path = DEFAULT_DB_PATH) -> dict | None:
    """Return full details for a single scan including all findings."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        scan_row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not scan_row:
            return None

        findings = conn.execute(
            """
            SELECT
                f.*,
                p.name AS package_name
            FROM findings f
            JOIN packages p ON p.id = f.package_id
            WHERE f.scan_id = ?
            ORDER BY
                CASE f.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE 5
                END
            """,
            (scan_id,),
        ).fetchall()

        return {
            "scan": dict(scan_row),
            "findings": [dict(f) for f in findings],
        }


def get_findings_for_package(
    package_name: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Return all findings ever recorded for a given package name across all scans."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                f.*,
                p.name  AS package_name,
                p.version AS package_version,
                s.started_at AS scan_started_at
            FROM findings f
            JOIN packages p ON p.id = f.package_id
            JOIN scans   s ON s.id = f.scan_id
            WHERE p.name = ?
            ORDER BY s.started_at DESC
            """,
            (package_name,),
        ).fetchall()
        return [dict(row) for row in rows]


def compare_scans(
    old_scan_id: str,
    new_scan_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """
    Compare two scans and return a structured diff.

    Returns a dict with:
        old_scan        — scan metadata for the baseline
        new_scan        — scan metadata for the current
        severity_delta  — {CRITICAL, HIGH, MEDIUM, LOW} with old/new/delta values
        new_vulns       — list of findings present in new scan but not in old
        resolved_vulns  — list of findings present in old scan but not in new
        persisted_count — number of vulnerabilities in both scans
    """
    init_db(db_path)
    with get_connection(db_path) as conn:
        # Fetch metadata for both scans
        def _get_scan_meta(sid: str) -> dict | None:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (sid,)).fetchone()
            return dict(row) if row else None

        old_meta = _get_scan_meta(old_scan_id)
        new_meta = _get_scan_meta(new_scan_id)

        if not old_meta:
            raise ValueError(f"Scan not found: {old_scan_id}")
        if not new_meta:
            raise ValueError(f"Scan not found: {new_scan_id}")

        # Fetch findings as (package_name, ecosystem, vulnerability_id) tuples
        def _get_findings_set(sid: str) -> dict[tuple, dict]:
            """
            Return {(package_name, ecosystem, vulnerability_id): finding_row} for a scan.

            Identity is (package_name, ecosystem, vulnerability_id) so that:
              - The same CVE on the same package in the same ecosystem is always
                the same finding, regardless of which scan it belongs to.
              - Package rows from different scans never share IDs, so we must
                never use the SQLite package_id as a cross-scan key.
            """
            rows = conn.execute(
                """
                SELECT f.vulnerability_id,
                       f.severity,
                       f.fixed_version,
                       f.ecosystem,
                       p.name    AS package_name,
                       p.version AS installed_version
                FROM findings f
                JOIN packages p ON p.id = f.package_id
                WHERE f.scan_id = ?
                """,
                (sid,),
            ).fetchall()
            result = {}
            for r in rows:
                key = (
                    r["package_name"],
                    r["ecosystem"],
                    r["vulnerability_id"],
                )
                result[key] = dict(r)
            return result

        old_findings = _get_findings_set(old_scan_id)
        new_findings = _get_findings_set(new_scan_id)

        old_keys = set(old_findings.keys())
        new_keys = set(new_findings.keys())

        new_vuln_keys = new_keys - old_keys       # appeared in new scan
        resolved_keys = old_keys - new_keys       # gone from new scan
        persisted_keys = old_keys & new_keys      # in both

        # Severity counts per scan
        def _severity_counts(findings: dict) -> dict[str, int]:
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings.values():
                sev = f.get("severity") or "LOW"
                if sev in counts:
                    counts[sev] += 1
            return counts

        old_sev = _severity_counts(old_findings)
        new_sev = _severity_counts(new_findings)

        severity_delta = {
            sev: {
                "old": old_sev[sev],
                "new": new_sev[sev],
                "delta": new_sev[sev] - old_sev[sev],
            }
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }

        # Build detail lists for new and resolved
        def _detail(key: tuple, findings: dict) -> dict:
            pkg_name, ecosystem, vuln_id = key
            f = findings[key]
            return {
                "package": pkg_name,
                "ecosystem": ecosystem,
                "installed_version": f["installed_version"],
                "vulnerability_id": vuln_id,
                "severity": f.get("severity"),
                "fixed_version": f.get("fixed_version"),
            }

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}

        new_vulns = sorted(
            [_detail(k, new_findings) for k in new_vuln_keys],
            key=lambda x: (sev_order.get(x["severity"], 4), x["package"]),
        )
        resolved_vulns = sorted(
            [_detail(k, old_findings) for k in resolved_keys],
            key=lambda x: (sev_order.get(x["severity"], 4), x["package"]),
        )

        return {
            "old_scan": old_meta,
            "new_scan": new_meta,
            "severity_delta": severity_delta,
            "new_vulns": new_vulns,
            "resolved_vulns": resolved_vulns,
            "persisted_count": len(persisted_keys),
        }
