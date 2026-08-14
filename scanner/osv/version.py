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
) -> tuple[bool, str | None, str | None]:
    """
    Evaluate if installed_ver is vulnerable under target_ecosystem based on OSV affected entries.

    Returns:
        (is_vulnerable, fixed_version, match_reason)
    """
    if not installed_ver or not affected_list:
        return False, None, None

    target_eco_upper = target_ecosystem.upper()

    # 1. Filter affected list strictly matching target_ecosystem
    matching_affected = []
    for aff in affected_list:
        pkg_eco = (aff.get("package", {}).get("ecosystem") or "").upper()
        if not pkg_eco:
            continue
        # Exact match or matching prefix (e.g. Debian:13 matches Debian:13)
        if pkg_eco == target_eco_upper or target_eco_upper in pkg_eco or pkg_eco in target_eco_upper:
            matching_affected.append(aff)

    if not matching_affected:
        # Advisory does not apply to target_ecosystem!
        return False, None, None

    for aff in matching_affected:
        # Check ranges (ECOSYSTEM / SEMVER / GIT)
        ranges = aff.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            introduced = None
            fixed = None

            for ev in events:
                if isinstance(ev, dict):
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]

            # Case A: Range has a fixed version
            if fixed:
                # If installed_ver < fixed:
                is_less = compare_versions(installed_ver, "lt", fixed, target_ecosystem)
                if is_less:
                    # Check introduced if present and not "0"
                    if introduced and introduced != "0":
                        is_ge_intro = compare_versions(installed_ver, "ge", introduced, target_ecosystem)
                        if not is_ge_intro:
                            continue # Installed version is older than introduced

                    reason = f"Installed {installed_ver} < fixed {fixed} in {target_ecosystem}"
                    return True, fixed, reason
                else:
                    # Installed version is >= fixed -> Patched!
                    continue

            # Case B: Range has introduced but no fixed version (unpatched / active vuln)
            elif introduced:
                if introduced == "0" or compare_versions(installed_ver, "ge", introduced, target_ecosystem):
                    reason = f"Installed {installed_ver} >= introduced {introduced} (unpatched in {target_ecosystem})"
                    return True, "None", reason

        # Check explicit versions list if present
        versions_list = aff.get("versions", [])
        if versions_list and installed_ver in versions_list:
            reason = f"Installed {installed_ver} explicitly listed in affected versions for {target_ecosystem}"
            return True, "None", reason

    return False, None, None
