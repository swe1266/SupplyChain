import json
from datetime import datetime
from genai.analyzer import analyze_threat

def log_event(runtime, threats):
    entry = {
        "time": datetime.now().isoformat(),
        "runtime": runtime,
        "threats": threats
    }

    # Save log
    with open("data/runtime.log", "a") as f:
        f.write(json.dumps(entry) + "\n")

    # AI Analysis
    ai_result = analyze_threat(entry)

    print("\n--- AI Threat Analysis ---")
    print(ai_result)

