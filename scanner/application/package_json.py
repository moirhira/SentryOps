import json
from pathlib import Path
from scanner.models import Dependency


def parse_package_json(path: Path = Path("package.json")) -> list[Dependency]:
    """Parse a package.json file and return a list of npm dependencies."""
    packages = []

    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = version.lstrip("^~") if isinstance(version, str) else version
            packages.append(Dependency(
                name=name,
                version=clean_version,
                ecosystem="npm",
                source="package.json",
                location=str(path)
            ))

    return packages

