def calculate_z_score(current, mean, std):
    if std == 0:
        return 0
    return (current - mean) / std


def detect_anomaly(metrics, baseline, threshold=3):
    """
    Detect anomalies using Z-score method.
    Returns anomaly details and severity.
    """

    results = {}
    severity_score = 0

    for key in ["cpu", "memory", "network", "process_count"]:
        mean = baseline[f"{key}_mean"]
        std = baseline[f"{key}_std"]
        current = metrics[key]

        z = calculate_z_score(current, mean, std)

        if abs(z) > threshold:
            results[key] = {
                "z_score": round(z, 2),
                "status": "CRITICAL"
            }
            severity_score += 3

        elif abs(z) > 2:
            results[key] = {
                "z_score": round(z, 2),
                "status": "SUSPICIOUS"
            }
            severity_score += 2

        else:
            results[key] = {
                "z_score": round(z, 2),
                "status": "NORMAL"
            }

    return results, severity_score