import psutil
import json
from datetime import datetime

def get_running_processes():
    processes = set()
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name']:
                processes.add(proc.info['name'].lower())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return list(processes)

def is_python_active(processes):
    return any("python" in p for p in processes)

def has_network_activity():
    connections = psutil.net_connections(kind='inet')
    return len(connections) > 0

def collect_runtime_data():
    processes = get_running_processes()

    runtime_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "active_processes": processes,
        "active_python": is_python_active(processes),
        "network_activity": has_network_activity()
    }

    return runtime_data

def save_runtime_data(data):
    with open("data/runtime.json", "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    runtime = collect_runtime_data()
    save_runtime_data(runtime)
    print("[+] Runtime monitoring completed")
