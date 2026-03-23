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
        cve_id = v.get("id")
        aliases = v.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        severity_score = "UNKNOWN"
        if "severity" in v and len(v["severity"]) > 0:
            sev_data = v["severity"][0]
            severity_score = sev_data.get("score", "UNKNOWN")

        vulns.append({
            "id": cve_id,
            "summary": v.get("summary", "No summary provided"),
            "severity": severity_score,
            "references": v.get("references", [])
        })

    return vulns
