import subprocess
from scanner.models import Dependency


def get_installed_packages_dpkg() -> list[Dependency]:
    """Scan installed packages via dpkg-query (Debian/Ubuntu family)."""
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
        capture_output=True,
        text=True,
        check=True
    )

    dependencies = []

    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        name, version = line.split(" ", 1)
        dependencies.append(
            Dependency(name=name, version=version, ecosystem="dpkg")
        )
    return dependencies
