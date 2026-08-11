from pathlib import Path
from scanner.models import Dependency
from scanner.container.dockerfile import parse_dockerfile


def scan_container(base_dir: Path = Path(".")) -> list[Dependency]:
    """Scan container manifests (Dockerfile) in base_dir."""
    deps = []
    dockerfile_path = base_dir / "Dockerfile"
    if dockerfile_path.exists():
        deps.extend(parse_dockerfile(dockerfile_path))
    return deps


__all__ = [
    "parse_dockerfile",
    "scan_container",
]
