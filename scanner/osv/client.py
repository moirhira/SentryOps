import json
import re
import sys
import time
from pathlib import Path
import requests

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
    from scanner.models import Dependency
else:
    from scanner.models import Dependency

OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
CACHE_PATH = Path(".sentryops_cache.json")

_DEBIAN_LIKE = {"debian", "ubuntu", "raspbian"}


def get_osv_ecosystem(os_id: str, version: str) -> str:
    """
    Map a detected distro to the ecosystem string OSV.dev expects.
    e.g. ('debian', '13') -> 'Debian:13'
    """
    if os_id in _DEBIAN_LIKE:
        if os_id == "ubuntu":
            return f"Ubuntu:{version}"
        return f"Debian:{version}"
    raise ValueError(
        f"No OSV ecosystem mapping for distro '{os_id}'. "
        f"Check https://ossf.github.io/osv-schema/#defined-ecosystems for support."
    )


def normalize_debian_version(version: str) -> str:
    """
    Strip Debian's backport/revision suffixes for CVE matching/display.
    '25.01+dfsg-1~deb13u2' -> '25.01'
    '1.2.14-1'             -> '1.2.14'
    """
    v = version.split("+")[0].split("~")[0]
    v = v.split("-")[0]
    return v


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_PATH.write_text(json.dumps(cache, indent=2))
    except OSError as e:
        print(f"Warning: Failed to save cache: {e}")


def parse_vuln_details(v: dict) -> dict:
    """
    Extract summary/details and severity/urgency from OSV vulnerability dictionary.
    Handles Debian OSV schema specifics (details instead of summary, CVSS severity arrays, ecosystem_specific urgency).
    """
    summary = v.get("summary") or v.get("details") or "No summary available"

    severity_str = None
    sev_list = v.get("severity", [])
    if isinstance(sev_list, list) and sev_list:
        scores = [f"{s.get('type', '')}: {s.get('score', '')}".strip() for s in sev_list if isinstance(s, dict)]
        scores = [s for s in scores if s != ":"]
        if scores:
            severity_str = ", ".join(scores)

    if not severity_str and v.get("database_specific"):
        db_sev = v.get("database_specific", {}).get("severity")
        if db_sev:
            severity_str = str(db_sev)

    if not severity_str and v.get("affected"):
        urgencies = []
        for aff in v.get("affected", []):
            urgency = aff.get("ecosystem_specific", {}).get("urgency") if aff.get("ecosystem_specific") else None
            if urgency and urgency not in urgencies:
                urgencies.append(urgency)
        if urgencies:
            severity_str = f"Debian Urgency: {', '.join(urgencies)}"

    if not severity_str:
        severity_str = "No severity available"

    return {
        "id": v.get("id", "UNKNOWN"),
        "summary": summary,
        "severity": severity_str
    }


def check_package(name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Return a list of vuln dict: [{id, summary, severity}, ...]
    Return [] if no version (unpinned) or no vulns found.
    """
    if not name or not version:
        return []

    body = {
        "package": {
            "name": name,
            "ecosystem": ecosystem
        },
        "version": version
    }

    try:
        response = requests.post(OSV_QUERY_ENDPOINT, json=body, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(e)
        return []

    python_dict = response.json()

    seen = set()
    unique_vulns = []

    for vuln in python_dict.get("vulns", []):
        ids = {vuln["id"], *vuln.get("aliases", [])}

        if ids & seen:
            continue

        unique_vulns.append(vuln)
        seen.update(ids)

    normalized = []
    for vuln in unique_vulns:
        normalized.append(parse_vuln_details(vuln))

    print(f"Found {len(normalized)} unique vulnerabilities for {name}=={version} in {ecosystem}.")
    return normalized


def check_dependencies(
    dependencies: list[Dependency],
    os_id: str | None = None,
    os_version: str | None = None,
) -> dict[str, list[dict]]:
    """
    Batch-check any list of Dependency objects (Host, Application, Container).
    Automatically maps host distro ecosystems (dpkg/rpm) when os_id/os_version are provided.
    """
    cache = _load_cache()
    results: dict[str, list[dict]] = {}

    to_query: list[tuple[Dependency, str]] = []
    for dep in dependencies:
        if not dep.name or not dep.version:
            continue

        if dep.ecosystem in ("dpkg", "rpm") and os_id and os_version:
            target_ecosystem = get_osv_ecosystem(os_id, os_version)
        else:
            target_ecosystem = dep.ecosystem

        cache_key = f"{target_ecosystem}:{dep.name}=={dep.version}"
        if cache_key in cache:
            if cache[cache_key]:
                results[f"{dep.name}=={dep.version}"] = cache[cache_key]
        else:
            to_query.append((dep, target_ecosystem))

    if not to_query:
        return results

    BATCH_SIZE = 1000
    for i in range(0, len(to_query), BATCH_SIZE):
        chunk = to_query[i:i + BATCH_SIZE]
        queries = [
            {"package": {"name": dep.name, "ecosystem": eco}, "version": dep.version}
            for dep, eco in chunk
        ]

        try:
            resp = requests.post(OSV_BATCH_ENDPOINT, json={"queries": queries}, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Batch query failed: {e}")
            continue

        batch_results = resp.json().get("results", [])

        for (dep, eco), result in zip(chunk, batch_results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            cache_key = f"{eco}:{dep.name}=={dep.version}"

            if not vuln_ids:
                cache[cache_key] = []
                continue

            details = []
            for vid in vuln_ids:
                try:
                    detail_resp = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=10)
                    detail_resp.raise_for_status()
                    v = detail_resp.json()
                    details.append(parse_vuln_details(v))
                except requests.exceptions.RequestException as e:
                    print(f"Failed to fetch detail for {vid}: {e}")

            cache[cache_key] = details
            results[f"{dep.name}=={dep.version}"] = details

        time.sleep(0.5)

    _save_cache(cache)
    return results


def check_host_packages(
    dependencies: list[Dependency],
    os_id: str,
    os_version: str,
) -> dict[str, list[dict]]:
    """Alias for check_dependencies specific to host packages."""
    return check_dependencies(dependencies, os_id=os_id, os_version=os_version)


def is_actionable(vuln: dict) -> bool:
    """
    Debian Urgency entries (no CVSS score) are historical/disputed/non-issues.
    Only CVSS-scored entries represent a real, ranked vulnerability.
    """
    severity = vuln.get("severity", "")
    if not isinstance(severity, str):
        return False
    return any(severity.startswith(prefix) for prefix in ("CVSS_V2", "CVSS_V3", "CVSS_V4", "HIGH", "CRITICAL", "MEDIUM", "LOW"))


def filter_actionable_vulns(package_vulns: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Drop packages whose only hits are Debian Urgency (non-CVSS) noise."""
    filtered = {}
    for pkg, vulns in package_vulns.items():
        actionable = [v for v in vulns if is_actionable(v)]
        if actionable:
            filtered[pkg] = actionable
    return filtered


