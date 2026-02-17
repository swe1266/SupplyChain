import json

def load_correlated():
    with open("data/correlated.json", "r") as f:
        return json.load(f)

def load_runtime():
    with open("data/runtime.json", "r") as f:
        return json.load(f)

def calculate_risk(component, runtime):
    score = component.get("severity", 5)

    if component["runtime_status"] == "ACTIVE":
        score += 2

    if runtime["network_activity"]:
        score += 1

    if score >= 9:
        level = "HIGH"
    elif score >= 6:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level

def score_all():
    correlated = load_correlated()
    runtime = load_runtime()

    results = []

    for comp in correlated:
        score, level = calculate_risk(comp, runtime)
        comp["risk_score"] = score
        comp["risk_level"] = level
        results.append(comp)

    return results

if __name__ == "__main__":
    output = score_all()
    print(json.dumps(output, indent=4))

def get_scored_results():
    return score_all()
