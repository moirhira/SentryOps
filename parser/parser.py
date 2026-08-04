import requests




def check_package(name: str, version: str, ecosystem: str) -> list[dict]:
    """
    Return a list of vuln dict: [{id, summary, severity}, ...]
    Return [] if no version (unpinned) or no vulns found.
    """

    if not name :
        return []

    if not version:
        return []

    endpoint = "https://api.osv.dev/v1/query"

    body = {
        "package" : {
            "name" : name,
            "ecosystem" : ecosystem 
        },
        "version" : version
    }

    
    
    try:
        response = requests.post(endpoint, json=body, timeout=10)
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

    



if __name__ == "__main__":
    result = check_package(
        "requests",
        "2.28.1",
        "PyPI"
    )

    for vuln in result:
        print(vuln)


