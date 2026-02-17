import requests

def check_vulnerability_dynamic(package, version, ecosystem="Maven"):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem
        },
        "version": version
    }

    response = requests.post(url, json=payload, timeout=10)
    data = response.json()

    if "vulns" not in data:
        return []

    vulns = []
    for v in data["vulns"]:
        vulns.append({
            "id": v.get("id"),
            "summary": v.get("summary"),
            "severity": v.get("severity", []),
            "references": v.get("references", [])
        })

    return vulns
