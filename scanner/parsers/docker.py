from pathlib import Path
from .models import Dependency

def parse_dockerfile(path: Path) -> List[Dependency]:
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

        tokens = line.split()
        image = None

        for token in tokens[1:]:
            if token.startswith("--"):
                continue
            if token.upper() == "AS":
                break
            
            image = token
            break

        if image is None:
            continue

        if ":" in image:
            name, version = image.split(":", 1)
        else:
            name = image
            version = "latest"

        packages.append(Dependency(
            name=name,
            version=version,
            ecosystem="docker"
        ))

    return packages