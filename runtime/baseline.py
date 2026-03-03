import json
import os
import statistics
from runtime.collector import collect_metrics

BASELINE_FILE = "data/baseline.json"

def build_baseline(samples=120, interval=2):
    """
    Collect system metrics and compute mean + std deviation.
    """

    cpu_list = []
    memory_list = []
    network_list = []
    process_list = []

    print("[+] Building behavioral baseline...")

    for i in range(samples):
        metrics = collect_metrics()

        cpu_list.append(metrics["cpu"])
        memory_list.append(metrics["memory"])
        network_list.append(metrics["network"])
        process_list.append(metrics["process_count"])

        print(f"Collected sample {i+1}/{samples}")

    baseline = {
        "cpu_mean": statistics.mean(cpu_list),
        "cpu_std": statistics.stdev(cpu_list),

        "memory_mean": statistics.mean(memory_list),
        "memory_std": statistics.stdev(memory_list),

        "network_mean": statistics.mean(network_list),
        "network_std": statistics.stdev(network_list),

        "process_count_mean": statistics.mean(process_list),
        "process_count_std": statistics.stdev(process_list) 
    }

    os.makedirs("data", exist_ok=True)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print("[+] Baseline saved successfully.")
    return baseline


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        raise Exception("Baseline not found. Run build_baseline() first.")

    with open(BASELINE_FILE, "r") as f:
        return json.load(f)