import json

def calculate_dependency_risk(package_name, version, vulnerabilities, runtime_score=0):
    highest_severity = 0
    
    if vulnerabilities:
        for v in vulnerabilities:
            sev = v.get("severity", "UNKNOWN")
            if isinstance(sev, str):
                try:
                    score = float(sev)
                    highest_severity = max(highest_severity, score)
                except ValueError:
                    sev_map = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}
                    highest_severity = max(highest_severity, sev_map.get(sev.upper(), 5.0))
            elif isinstance(sev, (int, float)):
                highest_severity = max(highest_severity, float(sev))
        
        if highest_severity == 0:
            highest_severity = 5.0  # default if unparseable
            
    # Add a penalty if system runtime score is high
    risk_score = highest_severity + (runtime_score * 0.15)
    risk_score = min(10.0, round(risk_score, 1))
    
    if risk_score >= 9.0:
        level = "CRITICAL"
    elif risk_score >= 7.0:
        level = "HIGH"
    elif risk_score >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"
        
    return risk_score, level

def get_scored_results(sbom_data=None, runtime_score=0, runtime_risk="LOW"):
    if sbom_data is None:
        return []

    results = []
    for comp in sbom_data:
        vulns = comp.get("vulnerabilities", [])
        score, level = calculate_dependency_risk(comp.get("name"), comp.get("version"), vulns, runtime_score)
        
        # We merge back fields so it's a complete component representation
        results.append({
            "name": comp.get("name"),
            "version": comp.get("version"),
            "supplier": comp.get("supplier", "Unknown"),
            "license": comp.get("license", "Unknown"),
            "vulnerabilities": vulns,
            "risk_score": score,
            "risk_level": level
        })
        
    return results

if __name__ == "__main__":
    pass
