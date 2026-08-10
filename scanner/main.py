from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from scanner.osv.client import check_package
from scanner.parsers.requirements import parse_requirements


if __name__ == "__main__":
    # result = check_package(
    #     "requests",
    #     "2.28.1",
    #     "PyPI"
    # )

    # for vuln in result:
    #     print(vuln)
    # parse_requirements("requirements.txt")
    packages = parse_requirements(Path("requirements.txt"))

    for package in packages:
        vulns = check_package(
            package.name,
            package.version,
            package.ecosystem,
        )

        if vulns:
            print(f"{package.name}=={package.version or 'unversioned'}")
            for vuln in vulns:
                print(f"- {vuln['id']}: {vuln['summary']} ({vuln['severity']})")


