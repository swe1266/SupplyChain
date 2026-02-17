import random

ACTIVE_THREATS = []

def threat_check(sbom):
    if random.random() < 0.3:
        ACTIVE_THREATS.append({
            "library": "dependency-x",
            "issue": "Suspicious update detected"
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



