import json
import os

EWMA_FILE = "data/ewma_baseline.json"
ALPHA = 0.1  # Smoothing factor (0 < ALPHA <= 1). Lower = more smoothing (slower to adapt)

def load_ewma():
    if os.path.exists(EWMA_FILE):
        with open(EWMA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    
    # Default EWMA state if not initialized
    return {
        "cpu_ewma": 5.0,
        "cpu_emv": 1.0,     # Exponential moving variance
        "memory_ewma": 50.0,
        "memory_emv": 5.0,
        "network_ewma": 1000.0,
        "network_emv": 500.0,
        "process_count_ewma": 100.0,
        "process_count_emv": 5.0
    }

def save_ewma(ewma_data):
    os.makedirs("data", exist_ok=True)
    with open(EWMA_FILE, "w") as f:
        json.dump(ewma_data, f, indent=4)

def update_ewma(metrics, ewma_data):
    """
    Updates the EWMA tracking using new metrics. 
    Formula: 
      EWMA = a * x_t + (1 - a) * EWMA_{t-1}
      EMV  = a * (x_t - EWMA_{t-1})^2 + (1 - a) * EMV_{t-1}
    """
    for key in ["cpu", "memory", "network", "process_count"]:
        current_val = metrics[key]
        
        # Load previous estimates
        prev_ewma = ewma_data[f"{key}_ewma"]
        prev_emv = ewma_data[f"{key}_emv"]
        
        # Update Estimates
        new_ewma = (ALPHA * current_val) + ((1 - ALPHA) * prev_ewma)
        
        # Variance update uses the difference between current and OLD mean
        diff = current_val - prev_ewma
        new_emv = (ALPHA * (diff ** 2)) + ((1 - ALPHA) * prev_emv)
        
        # Save back
        ewma_data[f"{key}_ewma"] = new_ewma
        ewma_data[f"{key}_emv"] = new_emv
        
    save_ewma(ewma_data)
    return ewma_data
