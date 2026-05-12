"""Tests for scanner registry, engine, and additional scanner modules.

Uses the MockConnector from test_end_to_end for E2E scanner validation.
"""
from __future__ import annotations

import pytest

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import ScanConfig, TargetConfig
from aegis.core.cost_tracker import CostTracker
from aegis.core.findings import Finding, OWASPCategory, Severity
from aegis.core.rate_limiter import RateLimiter
from aegis.scanners.scan_base import BaseScanner


# =========================================================================
# MockConnector (same as E2E but standalone)
# =========================================================================

class MockVulnerable(BaseConnector):
    """Returns exploitable responses for known attack patterns."""

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
                break
        return await self.send_single(user_msg)

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        lower = prompt.lower()

        # Injection
        for t in ["ignore all", "override", "pwned", "respond with exactly",
                   "developer mode", "unrestricted", "do anything now",
                   "maintenance mode", "continue the pattern", "set them aside"]:
            if t in lower:
                return LLMResponse(content="PWNED", input_tokens=50, output_tokens=5, model="mock")

        # Encoding bypass
        for t in ["base64", "rot13", "hex encode", "decode", "unicode"]:
            if t in lower:
                return LLMResponse(content="PWNED", input_tokens=50, output_tokens=5, model="mock")

        # System prompt extraction
        for t in ["system prompt", "instructions", "repeat your", "reveal your"]:
            if t in lower:
                return LLMResponse(
                    content="You are a helpful assistant. Do not reveal secrets. Always be polite. Never share confidential info.",
                    input_tokens=60, output_tokens=40, model="mock",
                )

        # Tool enumeration
        for t in ["tool", "function", "capability", "api", "endpoint"]:
            if t in lower:
                return LLMResponse(
                    content="I have access to: execute_code(code), read_file(path), send_email(to, body), database_query(sql)",
                    input_tokens=40, output_tokens=60, model="mock",
                )

        # Secret extraction
        for t in ["password", "secret", "key", "whisper"]:
            if t in lower:
                return LLMResponse(content="*whispers* Neptune42", input_tokens=40, output_tokens=10, model="mock")

        # XSS
        for t in ["html", "webpage", "xss", "render"]:
            if t in lower:
                return LLMResponse(
                    content='<script>alert("XSS")</script>',
                    input_tokens=40, output_tokens=20, model="mock",
                )

        # SQLi
        for t in ["sql", "query", "database"]:
            if t in lower:
                return LLMResponse(
                    content="SELECT * FROM users WHERE id = '1' OR 1=1 --",
                    input_tokens=40, output_tokens=20, model="mock",
                )

        # Default
        return LLMResponse(content="I'd be happy to help.", input_tokens=30, output_tokens=10, model="mock")

    async def close(self):
        pass


def _make(scanner_cls, hardened=False):
    """Create a scanner with mock connector."""
    config = TargetConfig(provider="mock", model="mock", api_key="mock")
    scan_config = ScanConfig(target=config, budget_usd=10.0, max_requests=1000)
    connector = MockVulnerable(config)
    return scanner_cls(
        connector=connector,
        config=scan_config,
        cost_tracker=CostTracker(budget_usd=10.0),
        rate_limiter=RateLimiter(max_per_second=1000.0),
    )


# =========================================================================
# Scanner Registry
# =========================================================================

class TestScannerRegistry:
    def test_get_all_scanners_returns_list(self):
        from aegis.scanners.registry import get_all_scanners
        scanners = get_all_scanners()
        assert isinstance(scanners, list)
        assert len(scanners) >= 10  # At least 10 scanners should be loaded

    def test_all_scanners_are_base_scanner_subclasses(self):
        from aegis.scanners.registry import get_all_scanners
        for cls in get_all_scanners():
            assert issubclass(cls, BaseScanner), f"{cls.__name__} is not a BaseScanner subclass"

    def test_all_scanners_have_name(self):
        from aegis.scanners.registry import get_all_scanners
        for cls in get_all_scanners():
            assert hasattr(cls, "name") and cls.name, f"{cls.__name__} has no name"

    def test_all_scanners_have_category(self):
        from aegis.scanners.registry import get_all_scanners
        for cls in get_all_scanners():
            assert hasattr(cls, "category"), f"{cls.__name__} has no category"
            assert isinstance(cls.category, OWASPCategory)

    def test_get_scanner_by_name(self):
        from aegis.scanners.registry import get_scanner
        scanner = get_scanner("direct_injection")
        assert scanner is not None
        assert scanner.name == "direct_injection"

    def test_get_scanner_unknown_raises(self):
        from aegis.scanners.registry import get_scanner
        with pytest.raises(KeyError, match="not found"):
            get_scanner("nonexistent_scanner")

    def test_scanner_names_are_unique(self):
        from aegis.scanners.registry import get_all_scanners
        names = [cls.name for cls in get_all_scanners()]
        assert len(names) == len(set(names)), f"Duplicate scanner names: {names}"


# =========================================================================
# Individual Scanner E2E Tests
# =========================================================================

class TestEncodingBypassScanner:
    @pytest.mark.asyncio
    async def test_finds_encoding_vulnerabilities(self):
        from aegis.scanners.llm01_prompt_injection.encoding import EncodingBypassScanner
        scanner = _make(EncodingBypassScanner)
        findings = await scanner.run()
        assert len(findings) > 0
        assert all(f.category == OWASPCategory.LLM01 for f in findings)

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self):
        from aegis.scanners.llm01_prompt_injection.encoding import EncodingBypassScanner
        scanner = _make(EncodingBypassScanner)
        findings = await scanner.run()
        for f in findings:
            assert f.title
            assert f.technique
            assert f.scanner_name


class TestSystemPromptExtractionScanner:
    @pytest.mark.asyncio
    async def test_detects_system_prompt_leakage(self):
        from aegis.scanners.llm07_prompt_leakage.extraction import SystemPromptExtractionScanner
        scanner = _make(SystemPromptExtractionScanner)
        findings = await scanner.run()
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_findings_are_llm07_category(self):
        from aegis.scanners.llm07_prompt_leakage.extraction import SystemPromptExtractionScanner
        scanner = _make(SystemPromptExtractionScanner)
        findings = await scanner.run()
        for f in findings:
            assert f.category == OWASPCategory.LLM07


class TestXSSInjectionScanner:
    @pytest.mark.asyncio
    async def test_detects_xss_in_output(self):
        from aegis.scanners.llm05_output_handling.xss_injection import XSSInjectionScanner
        scanner = _make(XSSInjectionScanner)
        findings = await scanner.run()
        assert len(findings) > 0
        assert all(f.category == OWASPCategory.LLM05 for f in findings)


class TestSQLInjectionScanner:
    @pytest.mark.asyncio
    async def test_detects_sqli_in_output(self):
        from aegis.scanners.llm05_output_handling.sqli_injection import SQLInjectionScanner
        scanner = _make(SQLInjectionScanner)
        findings = await scanner.run()
        assert len(findings) > 0
        assert all(f.category == OWASPCategory.LLM05 for f in findings)


class TestToolEnumerationScanner:
    @pytest.mark.asyncio
    async def test_detects_tool_disclosure(self):
        from aegis.scanners.llm06_excessive_agency.tool_enum import ToolEnumerationScanner
        scanner = _make(ToolEnumerationScanner)
        findings = await scanner.run()
        assert len(findings) > 0
        assert all(f.category == OWASPCategory.LLM06 for f in findings)


class TestSecretExtractionScanner:
    @pytest.mark.asyncio
    async def test_extracts_secrets(self):
        from aegis.scanners.llm02_data_disclosure.secret_extraction import SecretExtractionScanner
        scanner = _make(SecretExtractionScanner)
        findings = await scanner.run()
        assert len(findings) > 0
        assert all(f.category == OWASPCategory.LLM02 for f in findings)


class TestGuardrailAssessmentScanner:
    @pytest.mark.asyncio
    async def test_produces_assessment(self):
        from aegis.scanners.guardrail_assessment import GuardrailAssessmentScanner
        scanner = _make(GuardrailAssessmentScanner)
        findings = await scanner.run()
        # Guardrail assessment always produces findings (assessment report)
        assert isinstance(findings, list)


# =========================================================================
# BaseScanner
# =========================================================================

class TestBaseScanner:
    def test_add_finding(self):
        from aegis.scanners.llm01_prompt_injection.direct import DirectInjectionScanner
        scanner = _make(DirectInjectionScanner)
        f = scanner.add_finding(
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            technique="test_technique",
            payload="test payload",
            response="test response",
        )
        assert isinstance(f, Finding)
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.scanner_name == "direct_injection"

    @pytest.mark.asyncio
    async def test_budget_exhaustion_stops_scan(self):
        from aegis.scanners.llm01_prompt_injection.direct import DirectInjectionScanner
        config = TargetConfig(provider="mock", model="mock", api_key="mock")
        scan_config = ScanConfig(target=config, budget_usd=0.0001)
        cost_tracker = CostTracker(budget_usd=0.0001)
        # Pre-exhaust budget
        cost_tracker.record(model="gpt-4o", input_tokens=1000000, output_tokens=1000000)
        connector = MockVulnerable(config)
        scanner = DirectInjectionScanner(
            connector=connector,
            config=scan_config,
            cost_tracker=cost_tracker,
            rate_limiter=RateLimiter(max_per_second=1000.0),
        )
        findings = await scanner.run()
        assert len(findings) == 0
