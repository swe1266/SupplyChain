import math
import json
import os
from monitor.alerts import add_alert

STATE_FILE = "data/ewma_state.json"

def load_ewma_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        # Handle corrupted or empty state files gracefully
        return {}

def save_ewma_state(state):
    os.makedirs("data", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)

def detect_anomaly(metrics, baseline=None, alpha=0.1):
    """
    Detect anomalies using Exponentially Weighted Moving Average (EWMA).
    Maintains a rolling state of mean and variance.
    """
    state = load_ewma_state()
    results = {}
    severity_score = 0
    messages = []

    for key in ["cpu", "memory", "network", "process_count"]:
        current = metrics[key]
        
        # Initialize state for this metric if not exists
        if key not in state:
            state[key] = {
                "mean": current,
                "variance": 1.0  # Initial variance guess
            }

        # 1. Get previous state
        old_mean = state[key]["mean"]
        old_variance = state[key]["variance"]

        # 2. Update Mean and Variance using EWMA formulas
        # New Mean = alpha * current + (1 - alpha) * old_mean
        new_mean = (alpha * current) + (1 - alpha) * old_mean
        
        # New Variance = alpha * (current - old_mean)^2 + (1 - alpha) * old_variance
        diff = current - old_mean
        new_variance = (alpha * (diff**2)) + (1 - alpha) * old_variance

        # 3. Calculate Dynamic Z-Score
        # Enforce a minimum std deviation of 1.0 to prevent division by zero/near-zero
        std = math.sqrt(new_variance)
        effective_std = max(std, 1.0) 
        z = (current - old_mean) / effective_std

        # 4. Determine Status based on Z-Score
        status = "NORMAL"
        if abs(z) > 4:
            status = "CRITICAL"
            severity_score += 3
            messages.append((f"Critical spike in {key} detected (Z: {round(z, 2)})", "CRITICAL"))
        elif abs(z) > 3.5:
            status = "CRITICAL"
            severity_score += 2
            messages.append((f"High behavior in {key} detected (Z: {round(z, 2)})", "CRITICAL"))
        elif abs(z) > 3:
            status = "SUSPICIOUS"
            severity_score += 1
            messages.append((f"Suspicious behavior in {key} detected (Z: {round(z, 2)})", "HIGH"))

        # 5. Update state for next calculation
        state[key]["mean"] = new_mean
        state[key]["variance"] = new_variance

        results[key] = {
            "z_score": round(z, 2),
            "status": status,
            "mean": round(new_mean, 2)
        }

    save_ewma_state(state)

    # Sort and add alerts
    for msg, sev in messages:
        add_alert(msg, severity=sev, source="RUNTIME")

    return results, severity_score