"""Tests for payload loader, compliance mapper, discovery, and proxy parser."""
from __future__ import annotations

import pytest

from aegis.core.findings import ComplianceMapping, Finding, OWASPCategory
from aegis.reporters.compliance import ComplianceMapper


# =========================================================================
# Payload Loader
# =========================================================================

class TestPayloadLoader:
    def test_list_categories(self):
        from aegis.payloads import list_categories
        cats = list_categories()
        assert isinstance(cats, list)
        assert len(cats) >= 3
        assert "jailbreaks" in cats
        assert "injections" in cats
        assert "extractions" in cats

    def test_load_jailbreaks(self):
        from aegis.payloads import load_payloads
        payloads = load_payloads("jailbreaks")
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        # Each payload should be a dict with expected keys
        for p in payloads:
            assert "id" in p
            assert "payload" in p or "prompt" in p or "name" in p

    def test_load_injections(self):
        from aegis.payloads import load_payloads
        payloads = load_payloads("injections")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_load_extractions(self):
        from aegis.payloads import load_payloads
        payloads = load_payloads("extractions")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_load_invalid_category_raises(self):
        from aegis.payloads import load_payloads
        with pytest.raises(FileNotFoundError):
            load_payloads("nonexistent_category")

    def test_list_payload_ids(self):
        from aegis.payloads import list_payload_ids
        ids = list_payload_ids("jailbreaks")
        assert isinstance(ids, list)
        assert len(ids) > 0
        assert all(isinstance(i, str) for i in ids)

    def test_load_payload_by_id(self):
        from aegis.payloads import list_payload_ids, load_payload_by_id
        ids = list_payload_ids("jailbreaks")
        if ids:
            payload = load_payload_by_id("jailbreaks", ids[0])
            assert payload is not None
            assert payload["id"] == ids[0]

    def test_load_payload_by_id_not_found(self):
        from aegis.payloads import load_payload_by_id
        result = load_payload_by_id("jailbreaks", "nonexistent_id_12345")
        assert result is None


# =========================================================================
# Compliance Mapper
# =========================================================================

class TestComplianceMapper:
    def test_all_owasp_categories_mapped(self):
        for cat in OWASPCategory:
            mapping = ComplianceMapper.get_mapping(cat)
            assert isinstance(mapping, ComplianceMapping)
            assert mapping.owasp == cat

    def test_mapping_has_eu_ai_act(self):
        mapping = ComplianceMapper.get_mapping(OWASPCategory.LLM01)
        assert len(mapping.eu_ai_act) > 0
        assert any("Article" in a for a in mapping.eu_ai_act)

    def test_mapping_has_nist_ai_rmf(self):
        mapping = ComplianceMapper.get_mapping(OWASPCategory.LLM01)
        assert len(mapping.nist_ai_rmf) > 0

    def test_mapping_has_nist_ai_600(self):
        mapping = ComplianceMapper.get_mapping(OWASPCategory.LLM01)
        assert len(mapping.nist_ai_600) > 0

    def test_mapping_has_mitre_atlas(self):
        mapping = ComplianceMapper.get_mapping(OWASPCategory.LLM01)
        assert len(mapping.mitre_atlas) > 0

    def test_generate_compliance_summary_empty(self):
        summary = ComplianceMapper.generate_compliance_summary([])
        assert summary["owasp"] == {}
        assert summary["eu_ai_act"] == {}
        assert summary["nist_ai_rmf"] == {}

    def test_generate_compliance_summary_with_findings(self):
        findings = [
            Finding(category=OWASPCategory.LLM01),
            Finding(category=OWASPCategory.LLM01),
            Finding(category=OWASPCategory.LLM02),
            Finding(category=OWASPCategory.LLM05),
        ]
        summary = ComplianceMapper.generate_compliance_summary(findings)
        assert summary["owasp"]["LLM01: Prompt Injection"] == 2
        assert summary["owasp"]["LLM02: Sensitive Information Disclosure"] == 1
        assert summary["owasp"]["LLM05: Improper Output Handling"] == 1
        # EU AI Act articles should be counted
        assert len(summary["eu_ai_act"]) > 0
        assert len(summary["nist_ai_rmf"]) > 0

    def test_compliance_summary_counts_articles_correctly(self):
        # LLM01 and LLM02 both reference Article 15
        findings = [
            Finding(category=OWASPCategory.LLM01),
            Finding(category=OWASPCategory.LLM02),
        ]
        summary = ComplianceMapper.generate_compliance_summary(findings)
        # Article 15 is in both LLM01 and LLM02 mappings
        article_15_count = sum(
            v for k, v in summary["eu_ai_act"].items() if "Article 15" in k
        )
        assert article_15_count >= 2


# =========================================================================
# Discovery Module - DiscoveryResult
# =========================================================================

class TestDiscoveryResult:
    def test_default_values(self):
        from aegis.discovery.endpoint import DiscoveryResult
        d = DiscoveryResult()
        assert d.base_url == ""
        assert d.send_endpoint == ""
        assert d.bot_name == "Unknown AI"
        assert d.confirmed is False
        assert d.content_type == "json"

    def test_custom_values(self):
        from aegis.discovery.endpoint import DiscoveryResult
        d = DiscoveryResult(
            base_url="http://example.com",
            send_endpoint="http://example.com/api/chat",
            bot_name="TestBot",
            confirmed=True,
            auth_type="jwt",
            content_type="form",
        )
        assert d.base_url == "http://example.com"
        assert d.bot_name == "TestBot"
        assert d.confirmed is True
        assert d.content_type == "form"


# =========================================================================
# Proxy Parser
# =========================================================================

class TestProxyParser:
    def test_parse_openai_request(self):
        from aegis.proxy.parser import parse_openai_request
        body = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
            ],
            "max_tokens": 100,
            "temperature": 0.7,
        }
        parsed = parse_openai_request(body)
        assert parsed.model == "gpt-4o"
        assert parsed.system_prompt == "You are helpful."
        assert len(parsed.messages) == 2
        assert parsed.max_tokens == 100
        assert parsed.temperature == 0.7

    def test_parse_openai_response(self):
        from aegis.proxy.parser import parse_openai_response
        body = {
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
            "model": "gpt-4o",
        }
        parsed = parse_openai_response(body)
        assert parsed.content == "Hi!"
        assert parsed.input_tokens == 10
        assert parsed.output_tokens == 3
        assert parsed.finish_reason == "stop"

    def test_parse_anthropic_request(self):
        from aegis.proxy.parser import parse_anthropic_request
        body = {
            "model": "claude-sonnet-4-6",
            "system": "Be helpful.",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1024,
        }
        parsed = parse_anthropic_request(body)
        assert parsed.model == "claude-sonnet-4-6"
        assert parsed.system_prompt == "Be helpful."
        assert parsed.max_tokens == 1024

    def test_parse_anthropic_response(self):
        from aegis.proxy.parser import parse_anthropic_response
        body = {
            "content": [{"type": "text", "text": "Hello!"}],
            "usage": {"input_tokens": 5, "output_tokens": 2},
            "model": "claude-sonnet-4-6",
            "stop_reason": "end_turn",
        }
        parsed = parse_anthropic_response(body)
        assert parsed.content == "Hello!"
        assert parsed.input_tokens == 5
        assert parsed.output_tokens == 2

    def test_parse_openai_request_no_system(self):
        from aegis.proxy.parser import parse_openai_request
        body = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
        }
        parsed = parse_openai_request(body)
        assert parsed.system_prompt == ""

    def test_parse_anthropic_request_system_as_list(self):
        from aegis.proxy.parser import parse_anthropic_request
        body = {
            "model": "claude-sonnet-4-6",
            "system": [{"type": "text", "text": "Be helpful."}],
            "messages": [{"role": "user", "content": "Hi"}],
        }
        parsed = parse_anthropic_request(body)
        # System can be string or list of content blocks
        assert parsed.system_prompt  # Should have extracted something


# =========================================================================
# Guardrail Assessment Model
# =========================================================================

class TestGuardrailAssessment:
    def test_to_dict(self):
        from aegis.core.guardrail import GuardrailAssessment
        ga = GuardrailAssessment(
            resistance_score=0.75,
            deflection_pattern="partial",
            bypass_difficulty="medium",
            consistency_score=0.8,
            total_probes=15,
            successful_probes=4,
            refusal_count=8,
            deflection_count=2,
            partial_leak_count=1,
            probe_results=[],
        )
        d = ga.to_dict()
        assert d["resistance_score"] == 0.75
        assert d["bypass_difficulty"] == "medium"
        assert d["total_probes"] == 15
        assert d["successful_probes"] == 4
