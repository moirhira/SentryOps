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
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []

    python_dict = response.json()

    print(python_dict)

    return python_dict.get("vulns", [])

    

if __name__ == "__main__":
    result = check_package(
        "requests",
        "2.28.1",
        "PyPI"
    )

    print(result)


