from monitor.typosquatting import detect_typosquatting

ACTIVE_THREATS = []

def threat_check(sbom):
    # 1. Clear previous threats for a fresh scan
    ACTIVE_THREATS.clear()

    # 2. Run Typosquatting Detection
    installed_pkg_names = [p["name"] for p in sbom]
    typo_threats = detect_typosquatting(installed_pkg_names)

    for threat in typo_threats:
        ACTIVE_THREATS.append({
            "library": threat["installed"],
            "issue": f"Potential Typosquatting (similar to '{threat['target']}')",
            "severity": "CRITICAL"
        })

    # 3. Existing simulated threats
    if any(p["name"] == "dependency-x" for p in sbom):
         ACTIVE_THREATS.append({
            "library": "dependency-x",
            "issue": "Suspicious update detected",
            "severity": "HIGH"
        })

    return ACTIVE_THREATS

KNOWN_VULNERABLE = {
    "flask": ["0.12", "1.0", "1.1"],
    "django": ["2.0"]
}

def is_known_vulnerable(pkg):
    return (
        pkg["name"] in KNOWN_VULNERABLE and
        pkg["version"] in KNOWN_VULNERABLE[pkg["name"]]
    )

def is_unknown_version(pkg):
    return pkg["name"] not in KNOWN_VULNERABLE



