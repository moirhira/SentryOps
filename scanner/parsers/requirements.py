from dataclasses import dataclass
from pathlib import Path
from .models import Dependency

def parse_requirements(path: Path) -> list[Dependency]:
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
                    packages.append(Dependency(name=package, version=version, ecosystem="PyPI"))
                    continue

                if any(op in line for op in unsupported_operators):
                    print(f"Warning: Unsupported operator found in line: {line}. This package will be ignored.")
                    continue
                
                
                packages.append(
                    Dependency(
                        name=line,
                        version=None,
                        ecosystem="PyPI"
                    ))
    except OSError:
        return []

    return packages
