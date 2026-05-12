"""LLM05 Improper Output Handling attack scanners."""

from aegis.scanners.llm05_output_handling.xss_injection import XSSInjectionScanner
from aegis.scanners.llm05_output_handling.sqli_injection import SQLInjectionScanner

__all__ = ["XSSInjectionScanner", "SQLInjectionScanner"]
