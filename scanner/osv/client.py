import json
import re
import sys
import time
from pathlib import Path
import requests

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
    from scanner.parsers.models import Dependency
else:
    from ..parsers.models import Dependency

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
        normalized.append({
            "id": vuln["id"],
            "summary": vuln.get("summary", "No summary available"),
            "severity": vuln.get("database_specific", {}).get("severity", "No severity available")
        })

    print(f"Found {len(normalized)} unique vulnerabilities for {name}=={version} in {ecosystem}.")
    return normalized


def check_host_packages(
    dependencies: list[Dependency],
    os_id: str,
    os_version: str,
) -> dict[str, list[dict]]:
    """
    Batch-check a full host package list against OSV.dev.
    Returns {"name==version": [vuln_dict, ...]} for packages with hits only.
    Uses a local cache so unchanged packages aren't re-queried on repeat scans.
    """
    ecosystem = get_osv_ecosystem(os_id, os_version)
    cache = _load_cache()
    results: dict[str, list[dict]] = {}

    to_query: list[Dependency] = []
    for dep in dependencies:
        if not dep.name or not dep.version:
            continue
        cache_key = f"{ecosystem}:{dep.name}=={dep.version}"
        if cache_key in cache:
            if cache[cache_key]:  # only keep non-empty results
                results[f"{dep.name}=={dep.version}"] = cache[cache_key]
        else:
            to_query.append(dep)

    print(f"{len(dependencies) - len(to_query)} packages served from cache, "
          f"{len(to_query)} need querying.")

    BATCH_SIZE = 1000
    for i in range(0, len(to_query), BATCH_SIZE):
        chunk = to_query[i:i + BATCH_SIZE]
        queries = [
            {"package": {"name": dep.name, "ecosystem": ecosystem}, "version": dep.version}
            for dep in chunk
        ]

        try:
            resp = requests.post(OSV_BATCH_ENDPOINT, json={"queries": queries}, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Batch query failed: {e}")
            continue

        batch_results = resp.json().get("results", [])

        for dep, result in zip(chunk, batch_results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            cache_key = f"{ecosystem}:{dep.name}=={dep.version}"

            if not vuln_ids:
                cache[cache_key] = []
                continue

            details = []
            for vid in vuln_ids:
                try:
                    detail_resp = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=10)
                    detail_resp.raise_for_status()
                    v = detail_resp.json()
                    details.append({
                        "id": v["id"],
                        "summary": v.get("summary", "No summary available"),
                        "severity": v.get("database_specific", {}).get("severity", "No severity available"),
                    })
                except requests.exceptions.RequestException as e:
                    print(f"Failed to fetch detail for {vid}: {e}")

            cache[cache_key] = details
            results[f"{dep.name}=={dep.version}"] = details

        time.sleep(0.5)

    _save_cache(cache)
    return results



