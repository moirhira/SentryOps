from pathlib import Path
import json
from typing import List, Dict

def parse_package_json(path: Path) -> List[Dict]:
    """
    Parse a package.json file and return a list of dependencies.

    Args:
        path (Path): The path to the package.json file.

    Returns:
        List[Dict]: A list of dictionaries representing the dependencies.
    """
    packages = []

    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": "npm"
            })

    return packages
