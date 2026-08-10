from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from scanner.osv import check_host_packages, check_package
from scanner.parsers.linux import get_host_info, scan_host
from scanner.parsers.requirements import parse_requirements


if __name__ == "__main__":
    host = get_host_info()
    print(f"Scanning Host: {host.os_name} ({host.architecture}) | OS ID: {host.os_id}, Version: {host.version}")

    packages = scan_host()
    print(f"Discovered {len(packages)} packages installed on host.")

    try:
        findings = check_host_packages(packages, os_id=host.os_id, os_version=host.version)
        print(f"\nVulnerability scan complete. Found matches in {len(findings)} package(s):")
        for pkg, vulns in findings.items():
            print(f"\n{pkg}:")
            for v in vulns:
                print(f"  - {v['id']} [{v['severity']}] - {v['summary']}")
    except ValueError as e:
        print(f"Skipping host OS vulnerability lookup: {e}")

