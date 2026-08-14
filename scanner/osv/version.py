"""
Debian-aware and ecosystem-specific version comparison for SentryOps OSV engine.
Uses `dpkg --compare-versions` for Debian/Ubuntu versions.
"""

import subprocess
from typing import Any


def compare_debian_versions(v1: str, op: str, v2: str) -> bool:
    """
    Compare two Debian package version strings using system `dpkg --compare-versions`.
    Operators: 'lt', 'le', 'eq', 'ne', 'ge', 'gt'.
    """
    if not v1 or not v2:
        return False
    try:
        res = subprocess.run(
            ["dpkg", "--compare-versions", v1, op, v2],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0
    except (FileNotFoundError, OSError):
        # Fallback to string comparison if dpkg binary is unavailable
        if op == "lt":
            return v1 < v2
        elif op == "le":
            return v1 <= v2
        elif op == "gt":
            return v1 > v2
        elif op == "ge":
            return v1 >= v2
        elif op == "eq":
            return v1 == v2
        elif op == "ne":
            return v1 != v2
        return False


def compare_versions(v1: str, op: str, v2: str, ecosystem: str = "dpkg") -> bool:
    """Compare two version strings according to ecosystem semantics."""
    eco_upper = (ecosystem or "").upper()
    if "DEBIAN" in eco_upper or "UBUNTU" in eco_upper or eco_upper == "DPKG":
        return compare_debian_versions(v1, op, v2)

    # For PyPI/NPM/generic ecosystems, use packaging/basic logic
    try:
        from packaging.version import parse as parse_ver
        pv1 = parse_ver(v1)
        pv2 = parse_ver(v2)
        if op == "lt":
            return pv1 < pv2
        elif op == "le":
            return pv1 <= pv2
        elif op == "gt":
            return pv1 > pv2
        elif op == "ge":
            return pv1 >= pv2
        elif op == "eq":
            return pv1 == pv2
        elif op == "ne":
            return pv1 != pv2
    except Exception:
        pass

    # Fallback to string comparison
    if op == "lt":
        return v1 < v2
    elif op == "le":
        return v1 <= v2
    elif op == "gt":
        return v1 > v2
    elif op == "ge":
        return v1 >= v2
    elif op == "eq":
        return v1 == v2
    elif op == "ne":
        return v1 != v2
    return False


def evaluate_affected_range(
    installed_ver: str,
    affected_list: list[dict[str, Any]],
    target_ecosystem: str
) -> tuple[bool, str | None, dict[str, Any] | None]:
    """
    Evaluate if installed_ver is vulnerable under target_ecosystem based on OSV affected entries.

    Returns:
        (is_vulnerable, fixed_version, match_info_dict)
    """
    if not installed_ver or not affected_list:
        return False, None, None

    target_eco_upper = target_ecosystem.upper()
    comparator_type = "dpkg" if ("DEBIAN" in target_eco_upper or "UBUNTU" in target_eco_upper or target_eco_upper == "DPKG") else "semver"

    # 1. Filter affected list strictly matching target_ecosystem
    matching_affected = []
    for aff in affected_list:
        pkg_eco = (aff.get("package", {}).get("ecosystem") or "").upper()
        if not pkg_eco:
            continue
        if pkg_eco == target_eco_upper or target_eco_upper in pkg_eco or pkg_eco in target_eco_upper:
            matching_affected.append(aff)

    if not matching_affected:
        return False, None, None

    # Filter out entries marked with 'unimportant' urgency by Debian Security Tracker
    non_unimportant = []
    for aff in matching_affected:
        urgency = aff.get("ecosystem_specific", {}).get("urgency") if aff.get("ecosystem_specific") else None
        if urgency == "unimportant":
            continue
        non_unimportant.append(aff)

    if not non_unimportant:
        return False, None, None

    # Priority 1: Check fixed version ranges across target_ecosystem entries
    fixed_versions = []
    for aff in non_unimportant:
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if isinstance(ev, dict) and "fixed" in ev:
                    fixed_versions.append(ev["fixed"])

    if fixed_versions:
        # Check if installed_ver is less than ANY fixed version
        for fix in fixed_versions:
            if compare_versions(installed_ver, "lt", fix, target_ecosystem):
                match_info = {
                    "ecosystem": target_ecosystem,
                    "introduced": "0",
                    "fixed": fix,
                    "comparison": f"installed ({installed_ver}) < fixed ({fix})",
                    "version_comparator": comparator_type,
                    "result": "affected",
                }
                return True, fix, match_info
        # Installed version is >= all fixed versions -> Patched!
        return False, fixed_versions[0], None

    # Priority 2: Unpatched / active vulnerability (no fixed version in range)
    for aff in non_unimportant:
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if isinstance(ev, dict) and "introduced" in ev:
                    intro = ev["introduced"]
                    if intro == "0" or compare_versions(installed_ver, "ge", intro, target_ecosystem):
                        match_info = {
                            "ecosystem": target_ecosystem,
                            "introduced": intro,
                            "fixed": None,
                            "comparison": f"installed ({installed_ver}) >= introduced ({intro})",
                            "version_comparator": comparator_type,
                            "result": "affected",
                        }
                        return True, "None", match_info

    return False, None, None
