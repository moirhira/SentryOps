from pathlib import Path
from scanner.models import Dependency
from scanner.application.requirements import parse_requirements
from scanner.application.package_json import parse_package_json


def scan_application(base_dir: Path = Path(".")) -> list[Dependency]:
    """Scan all application manifests (requirements.txt, package.json) in base_dir."""
    deps = []
    req_path = base_dir / "requirements.txt"
    if req_path.exists():
        deps.extend(parse_requirements(req_path))

    pkg_path = base_dir / "package.json"
    if pkg_path.exists():
        deps.extend(parse_package_json(pkg_path))

    return deps


__all__ = [
    "parse_requirements",
    "parse_package_json",
    "scan_application",
]
