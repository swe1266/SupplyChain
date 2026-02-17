import requests

OSV_URL = "https://api.osv.dev/v1/query"

def check_external_vuln(library, version):
    payload = {
        "package": {
            "name": library
        },
        "version": version
    }

    try:
        response = requests.post(OSV_URL, json=payload, timeout=5)
        data = response.json()
        return data.get("vulns", [])
    except Exception as e:
        return []
