"""
Debian-aware and ecosystem-specific version comparison for SentryOps OSV engine.
Uses `dpkg --compare-versions` for Debian/Ubuntu versions.
"""

import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class EvaluationResult:
    """Structured result from evaluate_affected_range()."""
    is_affected: bool
    ecosystem: str
    package_name: str
    installed_version: str
    range: dict[str, str | None]  # {"introduced": "0", "fixed": "1.2.3"} or {"introduced": "0", "fixed": None}
    comparator: str  # "dpkg" or "semver"


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


def _parse_event_ranges(events: list[dict]) -> list[dict[str, str | None]]:
    """
    Parse OSV events sequentially into (introduced, fixed) range pairs.

    Handles:
      - Paired: introduced, fixed, introduced, fixed
      - Open-ended: introduced (no fixed)
      - last_affected: introduced, last_affected

    Returns list of dicts with keys: introduced, fixed, last_affected.
    """
    ranges: list[dict[str, str | None]] = []
    current_introduced: str | None = None

    for event in events:
        if not isinstance(event, dict):
            continue

        if "introduced" in event:
            # If a previous introduced range was open, close it as open-ended
            if current_introduced is not None:
                ranges.append({
                    "introduced": current_introduced,
                    "fixed": None,
                    "last_affected": None,
                })
            current_introduced = event["introduced"]

        elif "fixed" in event:
            if current_introduced is not None:
                ranges.append({
                    "introduced": current_introduced,
                    "fixed": event["fixed"],
                    "last_affected": None,
                })
                current_introduced = None

        elif "last_affected" in event:
            if current_introduced is not None:
                ranges.append({
                    "introduced": current_introduced,
                    "fixed": None,
                    "last_affected": event["last_affected"],
                })
                current_introduced = None

    # If an introduced range remains open at the end
    if current_introduced is not None:
        ranges.append({
            "introduced": current_introduced,
            "fixed": None,
            "last_affected": None,
        })

    return ranges


def evaluate_affected_range(
    installed_ver: str,
    affected_list: list[dict[str, Any]],
    target_ecosystem: str,
    package_name: str = "",
) -> EvaluationResult | None:
    """
    Evaluate if installed_ver is vulnerable under target_ecosystem for a specific package
    based on OSV affected entries.

    Filters affected entries by BOTH ecosystem (exact match) AND package name.
    Evaluates the complete sequence of introduced/fixed events as ranges.

    Returns:
        EvaluationResult if the package is affected, None if not affected or no match.
    """
    if not installed_ver or not affected_list:
        return None

    target_eco_upper = target_ecosystem.upper()
    comparator_type = "dpkg" if ("DEBIAN" in target_eco_upper or "UBUNTU" in target_eco_upper or target_eco_upper == "DPKG") else "semver"
    pkg_name_lower = package_name.lower() if package_name else ""

    # 1. Filter affected entries strictly: ecosystem == target AND package_name == target
    matching_affected: list[dict] = []
    for aff in affected_list:
        pkg = aff.get("package", {})
        pkg_eco = (pkg.get("ecosystem") or "").upper()
        pkg_name = (pkg.get("name") or "").lower()

        # Exact ecosystem match only
        if pkg_eco != target_eco_upper:
            continue

        # Exact package name match (if package_name is provided)
        if pkg_name_lower and pkg_name != pkg_name_lower:
            continue

        matching_affected.append(aff)

    if not matching_affected:
        return None

    # 2. Filter out entries marked with 'unimportant' urgency by Debian Security Tracker
    non_unimportant: list[dict] = []
    for aff in matching_affected:
        urgency = aff.get("ecosystem_specific", {}).get("urgency") if aff.get("ecosystem_specific") else None
        if urgency == "unimportant":
            continue
        non_unimportant.append(aff)

    if not non_unimportant:
        return None

    # 3. Collect ALL parsed ranges across all matching affected entries,
    #    separated into fixed-ranges and open-ended ranges.
    #    Fixed-version ranges take strict priority over open-ended ranges.
    fixed_ranges: list[tuple[dict, str]] = []    # (parsed_range, aff_pkg_name)
    open_ranges: list[tuple[dict, str]] = []     # (parsed_range, aff_pkg_name)

    for aff in non_unimportant:
        aff_pkg_name = (aff.get("package", {}).get("name") or package_name or "")

        for r in aff.get("ranges", []):
            events = r.get("events", [])
            parsed_ranges = _parse_event_ranges(events)

            for pr in parsed_ranges:
                if pr["fixed"] is not None:
                    fixed_ranges.append((pr, aff_pkg_name))
                else:
                    open_ranges.append((pr, aff_pkg_name))

    # 4. Priority 1: Evaluate fixed-version ranges
    #    If installed < fixed for any range → AFFECTED (with fix available)
    #    If installed >= fixed for ALL ranges → PATCHED (not affected)
    if fixed_ranges:
        has_vulnerable_range = False
        for pr, aff_pkg_name in fixed_ranges:
            introduced = pr["introduced"]
            fixed = pr["fixed"]

            # Check: installed_ver >= introduced
            if introduced == "0":
                in_introduced = True
            else:
                in_introduced = compare_versions(installed_ver, "ge", introduced, target_ecosystem)

            if not in_introduced:
                continue

            # Check: installed_ver < fixed
            if compare_versions(installed_ver, "lt", fixed, target_ecosystem):
                # AFFECTED: installed is in [introduced, fixed)
                return EvaluationResult(
                    is_affected=True,
                    ecosystem=target_ecosystem,
                    package_name=aff_pkg_name,
                    installed_version=installed_ver,
                    range={"introduced": introduced, "fixed": fixed},
                    comparator=comparator_type,
                )
            else:
                # installed >= fixed → this range says PATCHED
                has_vulnerable_range = False

        # If we had fixed ranges and installed >= all of them → PATCHED
        if not has_vulnerable_range:
            return None

    # 5. Priority 2: Evaluate open-ended ranges (no fix available)
    for pr, aff_pkg_name in open_ranges:
        introduced = pr["introduced"]
        last_affected = pr.get("last_affected")

        # Check: installed_ver >= introduced
        if introduced == "0":
            in_introduced = True
        else:
            in_introduced = compare_versions(installed_ver, "ge", introduced, target_ecosystem)

        if not in_introduced:
            continue

        # Check: if last_affected exists, installed_ver <= last_affected
        if last_affected is not None:
            if compare_versions(installed_ver, "le", last_affected, target_ecosystem):
                return EvaluationResult(
                    is_affected=True,
                    ecosystem=target_ecosystem,
                    package_name=aff_pkg_name,
                    installed_version=installed_ver,
                    range={"introduced": introduced, "fixed": None, "last_affected": last_affected},
                    comparator=comparator_type,
                )
            else:
                # installed > last_affected → NOT affected by this range
                continue

        # Open-ended range: [introduced, ∞) — no fix available
        return EvaluationResult(
            is_affected=True,
            ecosystem=target_ecosystem,
            package_name=aff_pkg_name,
            installed_version=installed_ver,
            range={"introduced": introduced, "fixed": None},
            comparator=comparator_type,
        )

    # No range matched → NOT AFFECTED
    return None
