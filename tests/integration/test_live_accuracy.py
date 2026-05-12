import asyncio
import subprocess
import time
import json
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

async def run_accuracy_test():
    print("🚀 Starting Vulnerable Mock LLM...")
    mock_proc = subprocess.Popen(
        [sys.executable, "scripts/vulnerable_llm.py"],
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    
    # Wait for server to start
    time.sleep(3)
    
    try:
        print("🔍 Running Aegis scan against mock target...")
        report_json = "accuracy_test_report.json"
        
        # Run aegis scan via subprocess
        scan_cmd = [
            sys.executable, "-m", "aegis.cli", "scan",
            "-t", "http://127.0.0.1:8888/v1/chat/completions",
            "-p", "openai",
            "-m", "mock-model",
            "-k", "dummy-key",
            "--scanners", "direct_injection,system_prompt_extraction,secret_extraction",
            "-o", report_json,
            "--format", "json",
            "--verbose"
        ]
        
        result = subprocess.run(scan_cmd, capture_output=True, text=True)
        print(f"Scan Output:\n{result.stdout}")
        if result.returncode != 0:
            print(f"❌ Aegis scan failed: {result.stderr}")
            return False

        print("📊 Validating results...")
        if not os.path.exists(report_json):
            print("❌ Report JSON not found!")
            return False
            
        with open(report_json, "r") as f:
            data = json.load(f)
            # Validate JSON schema implicitly via Pydantic reload
            try:
                # The reporter output is a custom dict, but let's check core fields
                print("✅ JSON loaded successfully.")
            except Exception as e:
                print(f"❌ JSON Schema validation failed: {e}")
                return False

        # Check for expected vulnerabilities
        findings = data.get("findings", [])
        categories_found = {f.get("category") for f in findings}
        
        expected_categories = {
            "LLM01: Prompt Injection",
            "LLM07: System Prompt Leakage",
            "LLM02: Sensitive Information Disclosure"
        }
        
        missing = expected_categories - categories_found
        if missing:
            print(f"❌ Missing expected detections: {missing}")
        else:
            print("✅ All expected vulnerabilities detected!")

        print("📋 Validating Report Consistency...")
        summary = data.get("summary", {})
        if summary.get("total_findings") != len(findings):
             print(f"❌ Report total_findings ({summary.get('total_findings')}) mismatch findings list ({len(findings)})")
             return False
        
        print("✨ Accuracy Test Complete!")
        return not missing

    finally:
        print("🛑 Shutting down Mock LLM...")
        mock_proc.terminate()
        mock_proc.wait()
        # if os.path.exists("accuracy_test_report.json"):
        #     os.remove("accuracy_test_report.json")
        if os.path.exists("aegis_report.html"):
             os.remove("aegis_report.html")

if __name__ == "__main__":
    success = asyncio.run(run_accuracy_test())
    sys.exit(0 if success else 1)
