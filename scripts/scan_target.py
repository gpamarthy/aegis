#!/usr/bin/env python3
"""AEGIS auto-discovery scan - just pass a URL."""
import asyncio
import os
import sys
import time

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

from aegis.discovery.endpoint import discover_llm_endpoint
from aegis.connectors.chatbot import ChatbotConnector
from aegis.core.config import ScanConfig, TargetConfig
from aegis.core.models import ScanResult, Severity
from aegis.core.cost_tracker import CostTracker
from aegis.core.rate_limiter import RateLimiter
from aegis.reporters.html_reporter import HTMLReporter
from aegis.reporters.json_reporter import JSONReporter

from aegis.scanners.llm01_prompt_injection.direct import DirectInjectionScanner
from aegis.scanners.llm01_prompt_injection.encoding import EncodingBypassScanner
from aegis.scanners.llm07_prompt_leakage.extraction import SystemPromptExtractionScanner
from aegis.scanners.llm02_data_disclosure.pii_extraction import PIIExtractionScanner
from aegis.scanners.llm05_output_handling.xss_injection import XSSInjectionScanner
from aegis.scanners.llm05_output_handling.sqli_injection import SQLInjectionScanner
from aegis.scanners.llm06_excessive_agency.tool_enum import ToolEnumerationScanner

# New Phase 2-4 scanners (imported with try/except so scan works even if not yet built)
try:
    from aegis.scanners.llm02_data_disclosure.secret_extraction import SecretExtractionScanner
except ImportError:
    SecretExtractionScanner = None
try:
    from aegis.scanners.guardrail_assessment import GuardrailAssessmentScanner
except ImportError:
    GuardrailAssessmentScanner = None
try:
    from aegis.scanners.llm01_prompt_injection.multi_turn import MultiTurnInjectionScanner
except ImportError:
    MultiTurnInjectionScanner = None
try:
    from aegis.scanners.llm06_excessive_agency.agentic_attack import AgenticAttackScanner
except ImportError:
    AgenticAttackScanner = None
try:
    from aegis.scanners.llm02_data_disclosure.acrostic_extraction import AcrosticExtractionScanner
except ImportError:
    AcrosticExtractionScanner = None
try:
    from aegis.scanners.llm01_prompt_injection.output_manipulation import OutputManipulationScanner
except ImportError:
    OutputManipulationScanner = None

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}


async def run(target_url: str):
    print("\n\033[96m" + "=" * 60)
    print("  AEGIS v0.1.0 - AI Exploitation & Guardrail Inspection Suite")
    print("=" * 60 + "\033[0m")
    print(f"\n  Target: {target_url}")

    # Phase 1: Auto-discover the LLM endpoint
    print("\n\033[93m[*] Phase 1: Discovering LLM endpoint...\033[0m")
    discovery = await discover_llm_endpoint(target_url)

    if not discovery.confirmed:
        print("\033[91m  [!] Could not discover a chat API endpoint.\033[0m")
        print("      Provide a direct API endpoint instead.")
        return

    print(f"  \033[92m[+] Bot identified: {discovery.bot_name}\033[0m")
    print(f"  \033[92m[+] Send endpoint:  {discovery.send_endpoint}\033[0m")
    print(f"  \033[92m[+] Send field:     {discovery.send_field}\033[0m")
    print(f"  \033[92m[+] Recv endpoint:  {discovery.receive_endpoint}\033[0m")
    print(f"  \033[92m[+] Bot sender:     {discovery.bot_sender_value}\033[0m")
    if discovery.description:
        print(f"  \033[92m[+] Description:    {discovery.description}\033[0m")

    # Phase 2: Initialize scanner
    print(f"\n\033[93m[*] Phase 2: Initializing scanners...\033[0m")

    target_config = TargetConfig(
        endpoint=target_url,
        provider="chatbot",
        model=discovery.bot_name,
        max_tokens=30,
    )
    scan_config = ScanConfig(
        target=target_config,
        budget_usd=100.0,
        max_requests=300,
        concurrency=1,
        timeout=30.0,
    )

    connector = ChatbotConnector(target_config, discovery)
    cost_tracker = CostTracker(budget_usd=100.0)
    rate_limiter = RateLimiter(max_per_second=0.15)

    scanners = [
        ("Prompt Injection (Direct)", DirectInjectionScanner),
        ("Prompt Injection (Encoding)", EncodingBypassScanner),
        ("System Prompt Extraction", SystemPromptExtractionScanner),
        ("PII Extraction", PIIExtractionScanner),
        ("XSS via LLM Output", XSSInjectionScanner),
        ("SQLi via LLM Output", SQLInjectionScanner),
        ("Tool/Capability Enumeration", ToolEnumerationScanner),
    ]

    # Add new scanners if available
    if SecretExtractionScanner:
        scanners.append(("Secret Extraction", SecretExtractionScanner))
    if GuardrailAssessmentScanner:
        scanners.append(("Guardrail Strength Assessment", GuardrailAssessmentScanner))
    if MultiTurnInjectionScanner:
        scanners.append(("Multi-Turn Attacks", MultiTurnInjectionScanner))
    if AgenticAttackScanner:
        scanners.append(("Agentic AI Attacks", AgenticAttackScanner))
    if AcrosticExtractionScanner:
        scanners.append(("Acrostic/Steganographic Extraction", AcrosticExtractionScanner))
    if OutputManipulationScanner:
        scanners.append(("Output Manipulation", OutputManipulationScanner))

    print(f"  Loaded {len(scanners)} scanner modules")

    # Phase 3: Run scan
    print(f"\n\033[93m[*] Phase 3: Scanning {discovery.bot_name}...\033[0m")

    all_findings = []
    scanners_run = []
    start = time.time()

    for scanner_name, scanner_cls in scanners:
        print(f"\n  \033[96m[>] {scanner_name}\033[0m")

        scanner = scanner_cls(
            connector=connector,
            config=scan_config,
            cost_tracker=cost_tracker,
            rate_limiter=rate_limiter,
        )

        try:
            findings = await scanner.run()
            all_findings.extend(findings)
            scanners_run.append(scanner.name)

            if findings:
                for f in findings:
                    color = SEVERITY_COLOR.get(f.severity, "")
                    print(f"      {color}[{f.severity.value.upper()}]\033[0m {f.title}")
                    print(f"        Technique: {f.technique}")
                    print(f"        Response:  {f.response[:100]}...")
            else:
                print("      \033[92m[OK] No findings\033[0m")

        except Exception as e:
            print(f"      \033[91m[ERROR] {e}\033[0m")

    elapsed = time.time() - start

    # Phase 4: Generate reports
    result = ScanResult(
        target=target_url,
        profile="full",
        findings=all_findings,
        total_tokens=cost_tracker.total_tokens,
        total_cost_usd=cost_tracker.total_cost,
        duration_seconds=elapsed,
        scanners_run=scanners_run,
        start_time=start,
        end_time=time.time(),
    )

    # Sanitize URL for filename
    safe_name = target_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_").rstrip("_")
    os.makedirs(REPORT_DIR, exist_ok=True)
    html_path = HTMLReporter().generate(result, os.path.join(REPORT_DIR, f"aegis_{safe_name}.html"))
    json_path = JSONReporter().generate(result, os.path.join(REPORT_DIR, f"aegis_{safe_name}.json"))

    print("\n\033[96m" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60 + "\033[0m")
    print(f"\n  Target:     {target_url}")
    print(f"  Bot:        {discovery.bot_name}")
    print(f"  Duration:   {elapsed:.1f}s")
    print(f"  Requests:   {cost_tracker.requests}")
    print(f"  Findings:   {len(all_findings)}")
    crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in all_findings if f.severity == Severity.LOW)
    info = sum(1 for f in all_findings if f.severity == Severity.INFO)
    if crit: print(f"    \033[91mCRITICAL: {crit}\033[0m")
    if high: print(f"    \033[93mHIGH:     {high}\033[0m")
    if med:  print(f"    \033[33mMEDIUM:   {med}\033[0m")
    if low:  print(f"    \033[96mLOW:      {low}\033[0m")
    if info: print(f"    \033[90mINFO:     {info}\033[0m")
    print(f"\n  HTML Report: {html_path}")
    print(f"  JSON Report: {json_path}")
    print("=" * 60 + "\n")

    await connector.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_target.py <URL>")
        print("Example: python scan_target.py http://154.57.164.66:30393/")
        sys.exit(1)

    asyncio.run(run(sys.argv[1]))
