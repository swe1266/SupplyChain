import difflib
import importlib.metadata

# A curated list of highly popular/targeted Python packages to protect
POPULAR_PACKAGES = [
    "requests", "urllib3", "certifi", "idna", "charset-normalizer",
    "botocore", "boto3", "setuptools", "wheel", "pip", "typing-extensions",
    "s3transfer", "six", "python-dateutil", "numpy", "pandas", "Werkzeug",
    "Click", "Flask", "Jinja2", "itsdangerous", "MarkupSafe", "colorama",
    "PyYAML", "rsa", "cryptography", "cffi", "pycparser", "beautifulsoup4",
    "lxml", "soupsieve", "Django", "SQLAlchemy", "pydantic", "fastapi"
]

def load_installed_packages():
    """Returns a lowercased list of all installed packages on the system."""
    return [dist.name.lower() for dist in importlib.metadata.distributions()]

def detect_typosquatting(installed_packages=None):
    """
    Scans the installed packages against POPULAR_PACKAGES list.
    If a package name is highly similar (similarity > 0.8) to a popular package
    but NOT an exact match, it is flagged as a potential typosquatting attack.
    """
    if installed_packages is None:
        installed_packages = load_installed_packages()
        
    popular_lower = [p.lower() for p in POPULAR_PACKAGES]
    
    threats_found = []

    for installed_pkg in installed_packages:
        # Ignore identical exact matches (that's just installing the actual library!)
        if installed_pkg in popular_lower:
            continue
            
        for popular_pkg in popular_lower:
            # difflib calculates a Levenshtein-like ratio 0.0 to 1.0
            similarity = difflib.SequenceMatcher(None, installed_pkg, popular_pkg).ratio()
            
            # 0.8 is the typical magic number for Typosquatting heuristics
            if similarity > 0.8:
                threats_found.append({
                    "installed": installed_pkg,
                    "target": popular_pkg,
                    "similarity": round(similarity * 100, 1)
                })
                break # Move to next installed package
                
    return threats_found
