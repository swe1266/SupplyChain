from importlib.metadata import distributions

LAST_SBOM = []

def generate_sbom():
    sbom = []
    for dist in distributions():
        sbom.append({
            "name": dist.metadata['Name'].lower(),
            "version": dist.version
        })
    return sbom


def detect_new_versions(current_sbom):
    global LAST_SBOM

    if not LAST_SBOM:
        LAST_SBOM = current_sbom
        return []

    new_items = [p for p in current_sbom if p not in LAST_SBOM]
    LAST_SBOM = current_sbom
    return new_items
