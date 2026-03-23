import json
import os
from datetime import datetime

ALERTS_FILE = "data/alerts.json"

def get_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_alerts(alerts):
    os.makedirs("data", exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

def add_alert(message, severity="HIGH", source="RUNTIME"):
    alerts = get_alerts()
    # Update timestamp if same alert already exists to prevent spam
    for a in alerts:
        if a["message"] == message and a["source"] == source:
            a["timestamp"] = datetime.now().isoformat()
            save_alerts(alerts)
            return

    new_alert = {
        "id": f"ALT-{len(alerts) + 1}",
        "message": message,
        "severity": severity,
        "source": source,
        "timestamp": datetime.now().isoformat()
    }
    alerts.insert(0, new_alert)
    save_alerts(alerts[:50]) # keep latest 50 alerts
