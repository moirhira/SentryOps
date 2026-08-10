"""
Linux host scanning: detects the distro and collects installed packages
as Dependency objects, ready to feed into the vulnerability engine.
"""


import subprocess
import platform
import sys
from pathlib import Path
from dataclasses import dataclass

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
    from scanner.parsers.models import Dependency
else:
    from .models import Dependency



@dataclass(slots=True)
class HostInfo:
    os_id: str | None
    os_name: str | None
    version: str | None
    architecture: str | None


def get_os_info() -> dict[str, str]:
    """
    Parse /etc/os-release into a dict.
    This is the standard, distro-agnostic way to identify a Linux system —
    every major distro ships this file.
    """

    info: dict[str, str] = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    info[key] = value.strip('"')
    except FileNotFoundError:
        raise RuntimeError("Could not find /etc/os-release. Are you running Linux?")
    return info


def get_host_info() -> HostInfo:
    """Build a HostInfo summary from os-release + platform data."""

    os_info = get_os_info()

    return HostInfo(
        os_id = os_info.get("ID", "unknown").lower(),
        os_name = os_info.get("NAME", "unknown"),
        version = os_info.get("VERSION_ID", "unknown"),
        architecture = platform.machine(),
    )


def get_installed_packages_dpkg() -> list[Dependency]:
    """Scan installed packages via dpkg-query (Debian/Ubuntu family)."""
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
        capture_output=True,
        text=True,
        check=True
    )

    dependencies = []

    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        name, version = line.split(" ", 1)
        dependencies.append(
            Dependency(name=name, version=version, ecosystem="dpkg")
        )
    return dependencies

def get_installed_packages_rpm() -> list[Dependency]:
    """Scan installed packages via rpm (RHEL/Fedora/CentOS/Rocky/Alma family)."""
    result =subprocess.run(
        ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"],
        capture_output=True,
        text=True,
        check=True
    )

    dependencies = []

    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        name, version = line.split("\t")
        dependencies.append(
            Dependency(name=name, version=version, ecosystem="rpm")
        )
    return dependencies


_DPKG_FAMILY = {"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"}
_RPM_FAMILY = {"rhel", "fedora", "centos", "rocky", "almalinux", "amzn"}



def scan_host() -> list[Dependency]:
    """
    Detect the host distro via /etc/os-release (not binary presence on PATH)
    and return installed packages as Dependency objects.
    """

    os_info = get_os_info()
    os_id = os_info.get("ID", "").lower()
    id_like = os_info.get("ID_LIKE", "").lower().split()

    if os_id in _DPKG_FAMILY or bool(set(id_like) & _DPKG_FAMILY):
        return get_installed_packages_dpkg()
    if os_id in _RPM_FAMILY or bool(set(id_like) & _RPM_FAMILY):
        return get_installed_packages_rpm()
    else:
        raise RuntimeError(
            f"Unsupported distro: ID={os_id!r}, ID_LIKE={os_info.get('ID_LIKE', '')!r}. "
            f"Currently supported: dpkg-based and rpm-based distros."
        )


if __name__ == "__main__":
    host = get_host_info()
    print(f"Host: {host.os_name} ({host.architecture})")
    print(f"Distro ID: {host.os_id}, Version: {host.version}")
    print("-" * 40)

    packages = scan_host()
    print(f"Found {len(packages)} installed packages\n")
    for pkg in packages[:10]:
        print(f"  {pkg.name:<30} {pkg.version}")
    if len(packages) > 10:
        print(f"  ... and {len(packages) - 10} more")