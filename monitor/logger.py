import json
from datetime import datetime

def log_event(runtime, threats):
    entry = {
        "time": datetime.now().isoformat(),
        "runtime": runtime,
        "threats": threats
    }

    with open("data/runtime.log", "a") as f:
        f.write(json.dumps(entry) + "\n")
