import sys
import os
import math

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from runtime.anomaly import detect_anomaly, STATE_FILE
from threat.check import threat_check

def test_ewma_logic():
    print("--- Testing EWMA Anomaly Tracking ---")
    
    # Ensure fresh state
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    metrics = {"cpu": 10.0, "memory": 20.0, "network": 0, "process_count": 50}
    results, score = detect_anomaly(metrics, alpha=0.1)
    print(f"Initial Score: {score}")
    
    # Second call - same metrics (should be NORMAL)
    results, score = detect_anomaly(metrics, alpha=0.1)
    print(f"Results: {results}")
    print(f"Stable Score: {score}")
    assert score == 0, f"Expected 0 score for stable metrics, got {score}"
    
    # Third call - sudden spike (should be CRITICAL or SUSPICIOUS)
    spike_metrics = {"cpu": 95.0, "memory": 20.0, "network": 0, "process_count": 50}
    results, score = detect_anomaly(spike_metrics, alpha=0.1)
    print(f"Spike Score: {score}")
    assert score > 0, "Expected non-zero score for sudden spike"
    
    print("EWMA Logic: PASSED\n")

def test_typosquatting_integration():
    print("--- Testing Typosquatting Integration ---")
    
    # Create fake sbom with a typosquatted package
    fake_sbom = [
        {"name": "requests", "version": "2.25.1"}, 
        {"name": "reguests", "version": "1.0.0"} # Fake typosquat
    ]
    
    threats = threat_check(fake_sbom)
    print(f"Threats found: {threats}")
    
    # Verify that 'reguests' was flagged
    flagged = any("Potential Typosquatting" in t["issue"] and t["library"] == "reguests" for t in threats)
    assert flagged, "Typosquatted package 'reguests' was not flagged!"
    
    print("Typosquatting Integration: PASSED\n")

if __name__ == "__main__":
    try:
        test_ewma_logic()
        test_typosquatting_integration()
        print("ALL SECURITY VERIFICATIONS PASSED!")
    except AssertionError as e:
        print(f"VERIFICATION FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"AN UNEXPECTED ERROR OCCURRED: {e}")
        sys.exit(1)
