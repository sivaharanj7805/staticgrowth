import sys
import os
import json

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SCRIPT_DIR)

from prioritize_vulnerabilities import prioritize_with_openai

RESULTS_DIR = r"C:\Users\Sivaharan\staticgrowth\sentinel-results\20260422-191954"
FINDINGS_PATH = os.path.join(RESULTS_DIR, "all-findings.json")

def main():
    print(f"Loading findings from {FINDINGS_PATH}")
    with open(FINDINGS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    findings = data.get("findings", [])
    print(f"Loaded {len(findings)} findings.")
    
    print("Sending to prioritize_with_openai...")
    prioritized = prioritize_with_openai(findings, model="gpt-4o", api_key=os.environ.get("OPENAI_API_KEY"))
    
    print("\nRESULTS:")
    print(json.dumps(prioritized, indent=2))

if __name__ == "__main__":
    main()
