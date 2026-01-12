import json
import os
from ollama import chat


def ai_overview():

    ip = input(" target IP for ai feedback: ").strip()

    filename = f"{ip}_vuln_scan.json"

    if not os.path.exists(filename):
        print(f"\nfile not found: {filename}")
        print("Make sure the JSON file is in the same directory as this script.\n")
        return

    #load vulnerability report
    with open(filename, "r", encoding="utf-8") as f:
        report = json.load(f)

    #  structured security prompt
    prompt = f"""
You are a cybersecurity analyst.

A vulnerability scan was performed against {ip}.
Analyse the following JSON report and provide:

1. Overall security  summary
2. Critical and high-risk issues (prioritised)
3. Practical remediation steps
4. Likely false positives or missing context

Vulnerability Report JSON:
{json.dumps(report, indent=2)}
""".strip()

    # sends to Ollama
    response = chat(
        model="phi3",
        messages=[{"role": "user", "content": prompt}],
    )

    # prints results
    print("\n" + "=" * 80)
    print(response["message"]["content"])
    print("=" * 80 + "\n")

