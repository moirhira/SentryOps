import platform
from dataclasses import dataclass
from scanner.models import Dependency
from scanner.host.dpkg import get_installed_packages_dpkg
from scanner.host.rpm import get_installed_packages_rpm


@dataclass(slots=True)
class HostInfo:
    os_id: str | None
    os_name: str | None
    version: str | None
    architecture: str | None


_DPKG_FAMILY = {"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"}
_RPM_FAMILY = {"rhel", "fedora", "centos", "rocky", "almalinux", "amzn"}


def get_os_info() -> dict[str, str]:
    """Parse /etc/os-release into a dict."""
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
        os_id=os_info.get("ID", "unknown").lower(),
        os_name=os_info.get("NAME", "unknown"),
        version=os_info.get("VERSION_ID", "unknown"),
        architecture=platform.machine(),
    )


def scan_host() -> list[Dependency]:
    """Detect host distro via /etc/os-release and return installed dependencies."""
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
