from flask import Flask, render_template, jsonify, request
import psutil
import random
import json
import os

# ---------------- IMPORT PROJECT MODULES ----------------
from sbom.scan import generate_sbom
from sbom.vuln_checker import check_vulnerability_dynamic
from threat.check import threat_check
from vuln.external import check_external_vuln
from risk.score import get_scored_results
from monitor.ai_bot import generate_summary
from monitor.custom_scan import scan_all_libraries
from monitor.correlate import build_metrics
from monitor.logger import log_event

from runtime.collector import collect_metrics
from runtime.baseline import load_baseline, build_baseline
from runtime.anomaly import detect_anomaly
from runtime.scorer import classify_runtime_risk


# ---------------- APP INIT ----------------
app = Flask(__name__)


# ---------------- BASELINE INITIALIZATION ----------------
BASELINE_FILE = "data/baseline.json"

if not os.path.exists(BASELINE_FILE):
    print("[!] Baseline not found. Building baseline (one-time setup)...")
    baseline = build_baseline()
else:
    baseline = load_baseline()

# ---------------- HOME DASHBOARD ----------------
@app.route("/")
def home():
    sbom_data = generate_sbom()
    threat_data = threat_check(sbom_data)

    runtime_data = {
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent
    }
    metrics = build_metrics(sbom_data, runtime_data)

    # 5. Save correlated metrics
    with open("data/correlated.json", "w") as f:
        json.dump(metrics, f, indent=4)

    log_event(runtime_data, threat_data)
    return render_template(
        "home.html",
        sbom=sbom_data,
        threats=threat_data,
        runtime=runtime_data
        

    )

# ---------------- RUNTIME API ----------------
@app.route("/runtime")
def runtime_api():

    metrics = collect_metrics()

    anomaly_details, score = detect_anomaly(metrics, baseline)

    risk_level = classify_runtime_risk(score)

    return jsonify({
        "cpu": metrics["cpu"],
        "memory": metrics["memory"],
        "network": metrics["network"],
        "process_count": metrics["process_count"],
        "runtime_risk": risk_level,
        "anomaly_details": anomaly_details
    })

# ---------------- THREATS API (SIMULATED) ----------------
THREAT_POOL = [
    "Suspicious outbound connection",
    "Dependency tampering detected",
    "Unexpected process execution",
    "Unsigned package detected"
]

@app.route("/threats")
def threats_api():
    active = random.sample(THREAT_POOL, random.randint(0, 2))
    return jsonify(active)

# ---------------- RISK API ----------------
@app.route("/risk")
def risk_api():

    # Get SBOM vulnerability results
    sbom_data = sbom_api().get_json()

    # Get runtime metrics
    metrics = collect_metrics()
    anomaly_details, score = detect_anomaly(metrics, baseline)
    runtime_risk = classify_runtime_risk(score)

    # Combine into hybrid scoring
    results = get_scored_results(
        sbom_data=sbom_data,
        runtime_score=score,
        runtime_risk=runtime_risk
    )

    return jsonify(results)
# ---------------- SBOM + VULNERABILITY API ----------------
@app.route("/sbom")
def sbom_api():
    sbom_list = generate_sbom()
    result = []

    for pkg in sbom_list:
        vulns = check_vulnerability_dynamic(
            package=pkg["name"],
            version=pkg["version"],
            ecosystem="PyPI"
        )

        result.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "status": "VULNERABLE" if vulns else "OK",
            "vulnerabilities": vulns
        })

    return jsonify(result)

# ---------------- RISK-SCORED SCAN PAGE ----------------
@app.route("/scan")
def scan():
    with open("data/correlated.json") as f:
        results = json.load(f)

    return render_template(
        "scan_result.html",
        results=results
    )

# ---------------- CUSTOM LIBRARY SCAN (OLD FORM) ----------------
@app.route("/custom-scan", methods=["POST"])
def custom_scan():
    lib = request.form.get("library", "").lower()
    version = request.form.get("version", "")
    mode = request.form.get("mode", "all")

    if not lib or not version:
        return render_template(
            "scan_result.html",
            error="Library and version are required"
        )

    vulns = check_external_vuln(lib, version)

    if mode == "known":
        vulns = [v for v in vulns if v.get("id", "").startswith("CVE")]

    elif mode == "unknown" and not vulns:
        return render_template(
            "scan_result.html",
            unknown=True,
            library=lib,
            version=version
        )

    if vulns:
        return render_template(
            "scan_result.html",
            found=True,
            library=lib,
            version=version,
            vulns=vulns
        )

    return render_template(
        "scan_result.html",
        found=False,
        library=lib,
        version=version
    )

# ---------------- CUSTOM SCAN ALL (NEW) ----------------
@app.route("/custom-scan-all")
def custom_scan_all():
    """
    Scan all installed libraries + popular libraries.
    Returns dashboard with vulnerability & safe version suggestions.
    """
    results = scan_all_libraries()
    return render_template("scan_result.html", results=results)

# ---------------- AI SUMMARY (CHATBOT API) ----------------
@app.route("/ai_summary")
def ai_summary():
    # 1. Get fresh system state (same logic as home)
    sbom_data = generate_sbom()
    threat_data = threat_check(sbom_data)

    runtime_data = {
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent
    }

    # 2. Send structured data to AI
    summary_text = generate_summary(
        runtime=runtime_data,
        threats=threat_data,
        sbom=sbom_data
    )

    return jsonify({"summary": summary_text})


# Popular / recommended libraries to suggest even if not installed
POPULAR_LIBS = ["flask", "django", "requests", "numpy", "pandas", "scipy", "matplotlib"]

def get_safe_version(lib_name):
    """
    Suggest a safe version for a library.
    This can later query OSV or return latest if safe.
    """
    return "latest"

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)
