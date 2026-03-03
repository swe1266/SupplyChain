def classify_runtime_risk(score):
    if score >= 6:
        return "CRITICAL"
    elif score >= 3:
        return "SUSPICIOUS"
    else:
        return "NORMAL"