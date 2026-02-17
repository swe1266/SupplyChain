from datetime import datetime
import json

def load_sbom():
    with open("data/sbom.json", "r") as f:
        return json.load(f)

def load_runtime():
    with open("data/runtime.json", "r") as f:
        return json.load(f)

def correlate():
    sbom = load_sbom()
    runtime = load_runtime()

    correlated = []

    for component in sbom:
        correlated.append({
            "component": component["name"],
            "version": component["version"],
            "runtime_status": "ACTIVE" if runtime["active_python"] else "INACTIVE"
        })

    return correlated



def build_metrics(sbom_data, runtime_data):
    metrics = {
        "total_libraries": len(sbom_data),
        "vulnerable_count": 0,
        "outdated_count": 0,
        "unknown_version_count": 0,
        "critical_cve_count": 0,
        "cpu_usage": runtime_data.get("cpu", 0),
        "memory_usage": runtime_data.get("memory", 0),
        "runtime_anomaly": False,
        "scan_time": datetime.now().isoformat()
    }

    for lib in sbom_data:
        status = lib.get("status", "").upper()

        if status == "VULNERABLE":
            metrics["vulnerable_count"] += 1

        elif status == "OUTDATED":
            metrics["outdated_count"] += 1

        elif status == "UNKNOWN":
            metrics["unknown_version_count"] += 1

        if lib.get("severity", "").lower() == "critical":
            metrics["critical_cve_count"] += 1

    if metrics["cpu_usage"] > 80 or metrics["memory_usage"] > 85:
        metrics["runtime_anomaly"] = True

    return metrics

if __name__ == "__main__":
    result = correlate()

    with open("data/correlated.json", "w") as f:
        json.dump(result, f, indent=4)


    print("Correlation completed")