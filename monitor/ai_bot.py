import json
import os
from openai import OpenAI

# ---------------- CONFIG ----------------

# OPTION A: OpenAI Cloud
# client = OpenAI(api_key="your_openai_key_here")

# OPTION B: Ollama Local
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

MODEL_NAME = "llama3"   # change if needed


# ---------------- GENERATE SUMMARY ----------------

def generate_summary():
    """
    Reads correlated risk metrics and generates AI security summary.
    """

    try:
        with open("data/correlated.json") as f:
            metrics = json.load(f)
    except:
        return "No scan data available yet."

    prompt = f"""
    You are a cybersecurity analyst AI.

    Analyze the following supply chain security data and provide:
    - Overall risk level
    - Key vulnerabilities
    - Threat insights
    - Recommended actions

    Data:
    {json.dumps(metrics, indent=2)}
    """

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"AI Error: {str(e)}"
