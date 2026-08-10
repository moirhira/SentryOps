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


