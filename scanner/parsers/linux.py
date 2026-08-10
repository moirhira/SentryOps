"""
Linux host scanning: detects the distro and collects installed packages
as Dependency objects, ready to feed into the vulnerability engine.
"""


import subprocess
import platform
from dataclasses import dataclass
from .models import Dependency


@dataclass(slots=True)
class HostInfo:
    od_id: str | None
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
