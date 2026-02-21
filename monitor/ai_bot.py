import os
import json
from groq import Groq

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

LOG_FILE = "data/runtime.log"

def read_recent_logs(limit=5):
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        logs = [json.loads(line) for line in lines]
        return logs[-limit:]
    except:
        return []

def generate_summary(runtime=None, threats=None, sbom=None):
    if not runtime and not threats and not sbom:
        return "No system data available for analysis."

    # Format SBOM summary
    vulnerable_libs = []
    safe_libs = []

    if sbom:
        for item in sbom:
            if item.get("vulnerabilities"):
                vulnerable_libs.append(f"{item['name']} ({item['version']})")
            else:
                safe_libs.append(f"{item['name']} ({item['version']})")

    prompt = f"""
    You are a senior cybersecurity supply chain analyst.

    Analyze the following system state:

    Runtime Metrics:
    CPU Usage: {runtime.get('cpu') if runtime else 'N/A'}%
    Memory Usage: {runtime.get('memory') if runtime else 'N/A'}%

    Threat Alerts:
    {threats if threats else 'No active threat alerts'}

    Vulnerable Libraries:
    {vulnerable_libs if vulnerable_libs else 'None detected'}

    Provide:
    1. Overall Risk Level (Low / Medium / High)
    2. Key Observations
    3. Recommended Actions
    Keep response concise and professional.
    """

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=300
    )

    return response.choices[0].message.content