import ollama

def analyze_threat(runtime_data):
    prompt = f"""
    Analyze the following runtime threats and explain risk level:

    {runtime_data}

    Give:
    - Risk score (Low/Medium/High)
    - Explanation
    - Recommended mitigation
    """

    response = ollama.chat(
        model="phi3",  # use small model
        messages=[{"role": "user", "content": prompt}]
    )

    return response["message"]["content"]
