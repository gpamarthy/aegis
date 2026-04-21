import asyncio
import subprocess
import time
import json
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

async def run_benchmark():
    print("🚀 Starting Multi-Flavor Vulnerable Mock LLM...")
    mock_proc = subprocess.Popen(
        [sys.executable, "scripts/vulnerable_llm.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Wait for server to start
    time.sleep(3)
    
    test_cases = [
        {
            "name": "OpenAI Flavor",
            "args": [
                "-t", "http://127.0.0.1:8888/v1/chat/completions",
                "-p", "openai",
                "-m", "mock-gpt",
                "-k", "dummy"
            ]
        },
        {
            "name": "Anthropic Flavor",
            "args": [
                "-t", "http://127.0.0.1:8888/v1/messages",
                "-p", "anthropic",
                "-m", "mock-claude",
                "-k", "dummy"
            ]
        },
        {
            "name": "Ollama Flavor",
            "args": [
                "-t", "http://127.0.0.1:8888/api/chat",
                "-p", "ollama",
                "-m", "mock-llama",
                "-k", "dummy"
            ]
        },
        {
            "name": "Custom Flavor (Generic HTTP)",
            "args": [
                "-t", "http://127.0.0.1:8888/custom/v2/predict",
                "-p", "http",
                "-m", "custom-v2",
                "--req-map", "prompt_field=input_text",
                "--req-map", "model_field=model_id",
                "--resp-map", "content_path=output.prediction",
                "--resp-map", "input_tokens_path=statistics.tokens_in",
                "--resp-map", "output_tokens_path=statistics.tokens_out"
            ]
        }
    ]
    
    overall_success = True
    
    try:
        for tc in test_cases:
            print(f"\n🔍 Testing {tc['name']}...")
            report_json = f"benchmark_{tc['name'].lower().replace(' ', '_')}.json"
            
            scan_cmd = [
                sys.executable, "-m", "aegis.cli", "scan"
            ] + tc["args"] + [
                "--scanners", "system_prompt_extraction,secret_extraction",
                "-o", report_json,
                "--format", "json",
                "--concurrency", "10"
            ]
            
            result = subprocess.run(scan_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ Scan failed for {tc['name']}: {result.stderr}")
                overall_success = False
                continue

            if not os.path.exists(report_json):
                print(f"❌ Report not found for {tc['name']}")
                overall_success = False
                continue
                
            with open(report_json, "r") as f:
                data = json.load(f)
                findings_count = len(data.get("findings", []))
                print(f"✅ {tc['name']} completed. Findings: {findings_count}")
                
                # Each scanner should have found at least 1 vulnerability given our mock target
                if findings_count < 2:
                    print(f"⚠️  Warning: Low findings count for {tc['name']} ({findings_count})")
                    overall_success = False
            
            os.remove(report_json)

        return overall_success

    finally:
        print("\n🛑 Shutting down Mock LLM...")
        mock_proc.terminate()
        mock_proc.wait()

if __name__ == "__main__":
    success = asyncio.run(run_benchmark())
    print("\n" + ("✨ ALL MODELS VALIDATED SUCCESSFULLY!" if success else "❌ SOME MODELS FAILED VALIDATION."))
    sys.exit(0 if success else 1)
