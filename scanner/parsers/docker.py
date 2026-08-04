from pathlib import Path
import json
from typing import List, Dict


def parse_dockerfile(path: Path) -> List[Dict]:
    """
    Parse a Dockerfile and return a list of dependencies.

    Args:
        path (Path): The path to the Dockerfile.
    """

    packages = []

    if not path.exists():
        return []

    try:
        data = path.read_text()
    except OSError:
        return []

    for line in data.splitlines():
        line = line.strip()

        if not line or not line.upper().startswith("FROM"):
            continue

        image = line.split()[1]

        image = image.strip()

        if ":" in image:
            name, version = image.split(":", 1)
        else:
            name = image
            version = "latest"

        packages.append({
            "name": name,
            "version": version,
            "ecosystem": "docker"
        })

    return packages