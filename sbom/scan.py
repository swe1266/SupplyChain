from importlib.metadata import distributions

LAST_SBOM = []

def generate_sbom():
    sbom = []
    for dist in distributions():
        supplier = dist.metadata.get('Author', dist.metadata.get('Author-email', 'Unknown'))
        license_name = dist.metadata.get('License', 'Unknown')
        name = dist.metadata.get('Name', '')
        if not name:
            continue
        sbom.append({
            "name": name.lower(),
            "version": dist.version,
            "supplier": supplier,
            "license": license_name
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
