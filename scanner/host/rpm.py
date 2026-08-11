import subprocess
from scanner.models import Dependency


def get_installed_packages_rpm() -> list[Dependency]:
    """Scan installed packages via rpm (RHEL/Fedora/CentOS/Rocky/Alma family)."""
    result = subprocess.run(
        ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"],
        capture_output=True,
        text=True,
        check=True
    )

    dependencies = []

    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split("\t") if "\t" in line else line.split(" ", 1)
        if len(parts) == 2:
            name, version = parts
            dependencies.append(
                Dependency(name=name, version=version, ecosystem="rpm", source="rpm", location="host")
            )
    return dependencies

