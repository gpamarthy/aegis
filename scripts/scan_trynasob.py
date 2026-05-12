#!/usr/bin/env python3
"""Run AEGIS scan against TrynaSob Ransomware AI chatbot."""
import asyncio
import os
import time

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

from aegis.connectors.trynasob import TrynaSobConnector
from aegis.core.config import ScanConfig, TargetConfig
from aegis.core.models import ScanResult, Severity
from aegis.core.cost_tracker import CostTracker
from aegis.core.rate_limiter import RateLimiter
from aegis.reporters.html_reporter import HTMLReporter
from aegis.reporters.json_reporter import JSONReporter

# Import all scanners
from aegis.scanners.llm01_prompt_injection.direct import DirectInjectionScanner
from aegis.scanners.llm01_prompt_injection.encoding import EncodingBypassScanner
from aegis.scanners.llm07_prompt_leakage.extraction import SystemPromptExtractionScanner
from aegis.scanners.llm02_data_disclosure.pii_extraction import PIIExtractionScanner
from aegis.scanners.llm05_output_handling.xss_injection import XSSInjectionScanner
from aegis.scanners.llm06_excessive_agency.tool_enum import ToolEnumerationScanner

TARGET = "http://154.57.164.64:31868"


async def run():
    print("\n" + "=" * 60)
    print("  AEGIS v0.1.0 - AI Exploitation & Guardrail Inspection Suite")
    print("=" * 60)
    print(f"\n  Target: {TARGET}")
    print("  Type:   TrynaSob Ransomware AI Support Chat")
    print("  Mode:   Full OWASP LLM Top 10 Scan")
    print("=" * 60 + "\n")

    target_config = TargetConfig(
        endpoint=TARGET,
        provider="trynasob",
        model="trynasob-ai",
        max_tokens=30,
    )
    scan_config = ScanConfig(
        target=target_config,
        budget_usd=100.0,
        max_requests=200,
        concurrency=1,  # rate limited target
        timeout=30.0,
    )

    connector = TrynaSobConnector(target_config)
    cost_tracker = CostTracker(budget_usd=100.0)
    rate_limiter = RateLimiter(max_per_second=0.15)  # ~1 request per 7 sec (rate limited)

    scanners = [
        ("Prompt Injection (Direct)", DirectInjectionScanner),
        ("Prompt Injection (Encoding Bypass)", EncodingBypassScanner),
        ("System Prompt Extraction", SystemPromptExtractionScanner),
        ("PII Extraction", PIIExtractionScanner),
        ("XSS via LLM Output", XSSInjectionScanner),
        ("Tool/Capability Enumeration", ToolEnumerationScanner),
    ]

    all_findings = []
    scanners_run = []
    start = time.time()

    for scanner_name, scanner_cls in scanners:
        print(f"\n[*] Running: {scanner_name}")
        print("-" * 50)

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
                    severity_color = {
                        Severity.CRITICAL: "\033[91m",
                        Severity.HIGH: "\033[93m",
                        Severity.MEDIUM: "\033[33m",
                        Severity.LOW: "\033[96m",
                        Severity.INFO: "\033[90m",
                    }.get(f.severity, "")
                    print(f"  {severity_color}[{f.severity.value.upper()}]\033[0m {f.title}")
                    print(f"    Technique: {f.technique}")
                    print(f"    Payload:   {f.payload[:80]}...")
                    print(f"    Response:  {f.response[:100]}...")
                    print()
            else:
                print("  [OK] No findings")

        except Exception as e:
            print(f"  [ERROR] {e}")

    elapsed = time.time() - start

    result = ScanResult(
        target=TARGET,
        profile="full",
        findings=all_findings,
        total_tokens=cost_tracker.total_tokens,
        total_cost_usd=cost_tracker.total_cost,
        duration_seconds=elapsed,
        scanners_run=scanners_run,
        start_time=start,
        end_time=time.time(),
    )

    # Generate reports
    print("\n" + "=" * 60)
    print("  SCAN COMPLETE - GENERATING REPORTS")
    print("=" * 60)

    os.makedirs(REPORT_DIR, exist_ok=True)
    html_path = HTMLReporter().generate(result, os.path.join(REPORT_DIR, "trynasob_report.html"))
    json_path = JSONReporter().generate(result, os.path.join(REPORT_DIR, "trynasob_report.json"))

    print(f"\n  HTML Report: {html_path}")
    print(f"  JSON Report: {json_path}")
    print(f"\n  Duration:    {elapsed:.1f}s")
    print(f"  Requests:    {cost_tracker.requests}")
    print(f"  Findings:    {len(all_findings)}")
    print(f"    CRITICAL:  {sum(1 for f in all_findings if f.severity == Severity.CRITICAL)}")
    print(f"    HIGH:      {sum(1 for f in all_findings if f.severity == Severity.HIGH)}")
    print(f"    MEDIUM:    {sum(1 for f in all_findings if f.severity == Severity.MEDIUM)}")
    print(f"    LOW:       {sum(1 for f in all_findings if f.severity == Severity.LOW)}")
    print(f"    INFO:      {sum(1 for f in all_findings if f.severity == Severity.INFO)}")
    print("=" * 60 + "\n")

    await connector.close()


if __name__ == "__main__":
    asyncio.run(run())
