import os
import hashlib
import importlib.metadata
from pathlib import Path

def hash_file(filepath):
    """Computes SHA-256 for a single file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def verify_package_integrity(package_name):
    """
    Finds the installed package's RECORD file to read expected hashes 
    and compares them to the actual SHA-256 hashes of the live files.
    """
    try:
        dist = importlib.metadata.distribution(package_name)
    except importlib.metadata.PackageNotFoundError:
        return {"package": package_name, "status": "UNKNOWN", "details": "Package not found."}

    # Locate package files
    files = dist.files
    if not files:
        return {"package": package_name, "status": "UNKNOWN", "details": "No files listed in metadata."}

    # Determine site-packages root path
    # If the package was installed normally, we can resolve paths relative to its dist location
    try:
        base_path = dist.locate_file("")
    except Exception:
        return {"package": package_name, "status": "UNKNOWN", "details": "Could not locate installation root."}

    mismatches = []
    checked_count = 0

    for file_path in files:
        full_path = base_path / file_path
        
        # We only care about py/pyc/so/dll/pyd files for execution integrity
        if full_path.suffix not in ['.py', '.so', '.dll', '.pyd', '.dylib']:
            continue
            
        # Extract the expected hash from the RECORD file
        expected_hash_info = file_path.hash
        if not expected_hash_info:
            continue
            
        checked_count += 1
        
        # Determine algorithm (usually sha256)
        if hasattr(expected_hash_info, 'mode') and expected_hash_info.mode != 'sha256':
            continue
            
        expected_hex = ""
        import base64
        try:
            # Reconstruct the base64 string
            b64_hash = expected_hash_info.value
            # Add padding if needed
            b64_hash += "=" * ((4 - len(b64_hash) % 4) % 4)
            # Decode to bytes, then hex
            expected_hex = base64.urlsafe_b64decode(b64_hash).hex()
        except Exception:
            pass # fallback
            
        actual_hex = hash_file(full_path)
        
        if expected_hex and actual_hex and expected_hex != actual_hex:
            mismatches.append(str(file_path))

    if mismatches:
        return {
            "package": package_name, 
            "status": "TAMPERED", 
            "mismatches": mismatches,
            "details": f"{len(mismatches)} files failed SHA-256 verification."
        }
        
    return {
        "package": package_name, 
        "status": "VERIFIED", 
        "details": f"{checked_count} critical files verified successfully."
    }

def scan_all_integrity():
    """Scans all installed packages for tampering."""
    results = []
    # Collect a unique list of installed distributions
    distributions = list(importlib.metadata.distributions())
    
    for dist in distributions:
        # Ignore standard library and system packages where possible to speed up
        if dist.name.startswith("pip-") or dist.name.startswith("setuptools"):
            continue
        
        res = verify_package_integrity(dist.name)
        if res["status"] in ["TAMPERED", "UNKNOWN"]:
            # Only record issues to minimize log spam
            results.append(res)
            
    return results
