import requests
from requests.packages import package
from typing import Optional




def check_package(name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Return a list of vuln dict: [{id, summary, severity}, ...]
    Return [] if no version (unpinned) or no vulns found.
    """

    if not name :
        return []

    if not version:
        return []

    OSV_ENDPOINT = "https://api.osv.dev/v1/query"

    body = {
        "package" : {
            "name" : name,
            "ecosystem" : ecosystem 
        },
        "version" : version
    }

    
    
    try:
        response = requests.post(OSV_ENDPOINT, json=body, timeout=10)
        response.raise_for_status()
        
    except requests.exceptions.RequestException as e:
        print(e)
        return []

    python_dict = response.json()

    seen = set()
    unique_vulns = []



    for vuln in python_dict.get("vulns", []):
        ids = {vuln["id"], *vuln.get("aliases", [])}

        if ids & seen:
            continue

        unique_vulns.append(vuln)
        seen.update(ids)

    normalized = []
    for vuln in unique_vulns:
        normalized.append({
            "id": vuln["id"],
            "summary": vuln.get("summary", "No summary available"),
            "severity": vuln.get("database_specific", {}).get("severity", "No severity available")
        })

    return normalized

    


def parse_requirements(requirements_file: str) -> list[tuple[str, Optional[str], str]]:
    packages = []
    unsupported_operators = {">", "<", ">=", "<=", "~=", "!=", "==="}

    with open(requirements_file, "r") as file:
        for line in file:
            line = line.strip() 

            if not line or line.startswith("#"):
                continue

            if line.startswith(("git+", "-r", "--", "-e")):
                print(f"Warning: Unsupported line in requirements file: {line}. This package will be ignored.")
                continue


            if "==" in line:
                package, version = line.split("==", 1)
                packages.append((package, version, "PyPI"))
                continue

            if any(op in line for op in unsupported_operators):
                print(f"Warning: Unsupported operator found in line: {line}. This package will be ignored.")
                continue
            
            
            packages.append((line, None, "PyPI"))

    return packages

if __name__ == "__main__":
    # result = check_package(
    #     "requests",
    #     "2.28.1",
    #     "PyPI"
    # )

    # for vuln in result:
    #     print(vuln)
    parse_requirements("requirements.txt")


