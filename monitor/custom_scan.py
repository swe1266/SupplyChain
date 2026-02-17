from sbom.scan import generate_sbom
from vuln.external import check_external_vuln

# List of popular / recommended libraries to suggest
POPULAR_LIBS = ["flask", "django", "requests", "numpy", "pandas", "scipy", "matplotlib"]

def get_safe_version(lib_name):
    """
    Suggest a safe version for a library.
    This can query OSV or return latest if safe.
    """
    # For now, we just assume 'latest' is safe (replace with dynamic API query if needed)
    return "latest"

def scan_all_libraries():
    """
    Scan installed libraries and popular non-installed ones.
    Returns a list of results for dashboard.
    """
    # Step 1: Installed libraries
    installed = generate_sbom()
    installed_names = [l["name"] for l in installed]
    results = []

    for lib in installed:
        vulns = check_external_vuln(lib["name"], lib["version"])
        results.append({
            "name": lib["name"],
            "installed_version": lib["version"],
            "vulnerable": bool(vulns),
            "vulns": vulns,
            "recommended_version": get_safe_version(lib["name"])
        })

    # Step 2: Popular libraries not installed
    for lib_name in POPULAR_LIBS:
        if lib_name not in installed_names:
            recommended = get_safe_version(lib_name)
            results.append({
                "name": lib_name,
                "installed_version": None,
                "vulnerable": False,  # Not installed yet
                "vulns": [],
                "recommended_version": recommended
            })

    return results
