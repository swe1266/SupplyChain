import os
from openai import OpenAI

client = None

def get_client():
    global client
    if client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        client = OpenAI(api_key=api_key)
    return client

def generate_summary():
    try:
        with open("data/runtime.log") as f:
            lines = f.readlines()[-5:]  # last 5 events
    except FileNotFoundError:
        return "No monitoring data available."

    high_cpu = 0
    threats_found = 0

    for line in lines:
        data = eval(line)
        if data["runtime"]["cpu"] > 70:
            high_cpu += 1
        if data["threats"]:
            threats_found += 1

    if threats_found:
        return "Multiple security threats detected recently. Immediate attention recommended."

    if high_cpu:
        return "System experiencing high CPU usage but no active threats."

    return "System operating normally with no significant threats."
