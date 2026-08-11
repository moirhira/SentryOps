from pathlib import Path
from scanner.models import Dependency


def parse_requirements(path: Path = Path("requirements.txt")) -> list[Dependency]:
    packages = []
    unsupported_operators = {">", "<", ">=", "<=", "~=", "!=", "==="}

    if not path.exists():
        return []

    try:
        with path.open() as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith(("git+", "-r", "--", "-e")):
                    print(f"Warning: Unsupported line in requirements file: {line}. This package will be ignored.")
                    continue

                if "==" in line:
                    package, version = line.split("==", 1)
                    packages.append(Dependency(
                        name=package.strip(),
                        version=version.strip(),
                        ecosystem="PyPI",
                        source="requirements.txt",
                        location=str(path)
                    ))
                    continue

                if any(op in line for op in unsupported_operators):
                    print(f"Warning: Unsupported operator found in line: {line}. This package will be ignored.")
                    continue

                packages.append(
                    Dependency(
                        name=line,
                        version=None,
                        ecosystem="PyPI",
                        source="requirements.txt",
                        location=str(path)
                    ))

    except OSError:
        return []

    return packages
