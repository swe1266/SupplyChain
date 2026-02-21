import os
import json
from groq import Groq

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

LOG_FILE = "data/runtime.log"

def read_logs():
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return [json.loads(line) for line in lines]
    except:
        return []

def summarize_logs():
    logs = read_logs()

    if not logs:
        return "No logs available."

    # Limit to last 5 logs for speed
    log_text = "\n".join([str(log) for log in logs[-5:]])

    prompt = f"""
    You are a cybersecurity analyst.

    Analyze these runtime logs:

    {log_text}

    Provide:
    - Suspicious Activity
    - Risk Level (Low/Medium/High)
    - Recommended Action
    """

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=300
    )

    return response.choices[0].message.content