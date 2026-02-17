from flask import Flask, render_template, jsonify, request
import psutil
import random
import json


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

app = Flask(__name__)

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
    return jsonify({
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent
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
    summary_text = generate_summary()
    return jsonify({"summary": summary_text})


# Popular / recommended libraries to suggest even if not installed
POPULAR_LIBS = ["flask", "django", "requests", "numpy", "pandas", "scipy", "matplotlib"]

def get_safe_version(lib_name):
    """
    Suggest a safe version for a library.
    This can later query OSV or return latest if safe.
    """
    return "latest"

def scan_all_libraries():
    """
    Scan installed libraries + popular non-installed libraries.
    Returns results with vulnerabilities and recommended safe versions.
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





# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)
