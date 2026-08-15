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

    def to_match_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "range": self.range,
            "installed_version": self.installed_version,
            "comparator": self.comparator,
            "result": "affected" if self.is_affected else "not_affected",
        }


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

        if pkg_eco != target_eco_upper:
            continue

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

    # 3. Priority 1: Evaluate ranges with fixed versions first
    fixed_ranges: list[tuple[str, str, str]] = []
    for aff in non_unimportant:
        aff_pkg_name = (aff.get("package", {}).get("name") or package_name or "")
        for r in aff.get("ranges", []):
            events = r.get("events", [])
            for pr in _parse_event_ranges(events):
                if pr["fixed"] is not None:
                    fixed_ranges.append((pr["introduced"] or "0", pr["fixed"], aff_pkg_name))

    if fixed_ranges:
        for introduced, fixed, aff_pkg_name in fixed_ranges:
            if compare_versions(installed_ver, "lt", fixed, target_ecosystem):
                if introduced == "0" or compare_versions(installed_ver, "ge", introduced, target_ecosystem):
                    return EvaluationResult(
                        is_affected=True,
                        ecosystem=target_ecosystem,
                        package_name=aff_pkg_name,
                        installed_version=installed_ver,
                        range={"introduced": introduced, "fixed": fixed},
                        comparator=comparator_type,
                    )
        # Installed version is >= all fixed versions -> Patched!
        return None

    # 4. Priority 2: Evaluate open-ended ranges (no fix available)
    for aff in non_unimportant:
        aff_pkg_name = (aff.get("package", {}).get("name") or package_name or "")
        for r in aff.get("ranges", []):
            events = r.get("events", [])
            for pr in _parse_event_ranges(events):
                introduced = pr["introduced"] or "0"
                last_affected = pr["last_affected"]

                if introduced == "0" or compare_versions(installed_ver, "ge", introduced, target_ecosystem):
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
                        return EvaluationResult(
                            is_affected=True,
                            ecosystem=target_ecosystem,
                            package_name=aff_pkg_name,
                            installed_version=installed_ver,
                            range={"introduced": introduced, "fixed": None},
                            comparator=comparator_type,
                        )

    return None
