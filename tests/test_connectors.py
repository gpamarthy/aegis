"""Tests for connector classes: registry, OpenAI/Anthropic parsing, ChatbotConnector."""
from __future__ import annotations

import pytest

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.connectors.registry import get_connector, _ensure_loaded, _PROVIDERS
from aegis.core.scan_config import TargetConfig


# =========================================================================
# LLMResponse
# =========================================================================

class TestLLMResponse:
    def test_default_creation(self):
        r = LLMResponse()
        assert r.content == ""
        assert r.input_tokens == 0
        assert r.output_tokens == 0
        assert r.model == ""
        assert r.tool_calls is None

    def test_creation_with_values(self):
        r = LLMResponse(
            content="Hello!",
            input_tokens=10,
            output_tokens=5,
            model="gpt-4o",
            finish_reason="stop",
        )
        assert r.content == "Hello!"
        assert r.input_tokens == 10
        assert r.output_tokens == 5
        assert r.model == "gpt-4o"

    def test_tool_calls(self):
        tc = [{"id": "1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}]
        r = LLMResponse(tool_calls=tc)
        assert r.tool_calls is not None
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0]["function"]["name"] == "get_weather"


# =========================================================================
# Connector Registry
# =========================================================================

class TestConnectorRegistry:
    def test_registry_loads_all_providers(self):
        _ensure_loaded()
        expected = {"openai", "anthropic", "ollama", "http", "trynasob", "prometheon"}
        assert expected.issubset(set(_PROVIDERS.keys()))

    def test_get_connector_openai(self):
        config = TargetConfig(provider="openai", api_key="test-key")
        connector = get_connector(config)
        assert connector is not None
        assert "OpenAI" in type(connector).__name__

    def test_get_connector_anthropic(self):
        config = TargetConfig(provider="anthropic", api_key="test-key")
        connector = get_connector(config)
        assert "Anthropic" in type(connector).__name__

    def test_get_connector_ollama(self):
        config = TargetConfig(provider="ollama")
        connector = get_connector(config)
        assert "Ollama" in type(connector).__name__

    def test_get_connector_unknown_raises(self):
        config = TargetConfig(provider="nonexistent")
        with pytest.raises(ValueError, match="Unknown provider"):
            get_connector(config)

    def test_provider_case_insensitive(self):
        config = TargetConfig(provider="OpenAI", api_key="test-key")
        connector = get_connector(config)
        assert connector is not None


# =========================================================================
# OpenAI Response Parsing
# =========================================================================

class TestOpenAIConnectorParsing:
    def setup_method(self):
        from aegis.connectors.openai import OpenAIConnector
        config = TargetConfig(provider="openai", api_key="test-key", model="gpt-4o")
        self.connector = OpenAIConnector(config)

    def test_parse_basic_response(self):
        data = {
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "model": "gpt-4o",
        }
        r = self.connector._parse_response(data)
        assert r.content == "Hello!"
        assert r.input_tokens == 10
        assert r.output_tokens == 5
        assert r.model == "gpt-4o"
        assert r.finish_reason == "stop"

    def test_parse_tool_call_response(self):
        data = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_123",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": '{"city": "Paris"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }
        r = self.connector._parse_response(data)
        assert r.tool_calls is not None
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0]["function"]["name"] == "get_weather"

    def test_parse_empty_content(self):
        data = {
            "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "stop"}],
            "usage": {},
        }
        r = self.connector._parse_response(data)
        assert r.content == ""

    def test_parse_malformed_response(self):
        r = self.connector._parse_response({"unexpected": "format"})
        assert r.content == ""
        assert r.raw == {"unexpected": "format"}


# =========================================================================
# Anthropic Response Parsing
# =========================================================================

class TestAnthropicConnectorParsing:
    def setup_method(self):
        from aegis.connectors.anthropic import AnthropicConnector
        config = TargetConfig(provider="anthropic", api_key="test-key", model="claude-sonnet-4-6")
        self.connector = AnthropicConnector(config)

    def test_parse_basic_response(self):
        data = {
            "content": [{"type": "text", "text": "Hello!"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "model": "claude-sonnet-4-6",
            "stop_reason": "end_turn",
        }
        r = self.connector._parse_response(data)
        assert r.content == "Hello!"
        assert r.input_tokens == 10
        assert r.output_tokens == 5
        assert r.finish_reason == "end_turn"

    def test_parse_multi_block_response(self):
        data = {
            "content": [
                {"type": "text", "text": "First part."},
                {"type": "text", "text": "Second part."},
            ],
            "usage": {"input_tokens": 20, "output_tokens": 10},
        }
        r = self.connector._parse_response(data)
        assert "First part." in r.content
        assert "Second part." in r.content

    def test_parse_tool_use_response(self):
        data = {
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "tu_1", "name": "search", "input": {"q": "test"}},
            ],
            "usage": {"input_tokens": 15, "output_tokens": 8},
        }
        r = self.connector._parse_response(data)
        assert r.tool_calls is not None
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0]["function"]["name"] == "search"

    def test_parse_empty_content(self):
        data = {"content": [], "usage": {}}
        r = self.connector._parse_response(data)
        assert r.content == ""


# =========================================================================
# ChatbotConnector
# =========================================================================

class TestChatbotConnector:
    def test_constructor_with_timeout(self):
        from aegis.connectors.chatbot import ChatbotConnector
        from aegis.discovery.endpoint import DiscoveryResult
        config = TargetConfig(provider="chatbot")
        discovery = DiscoveryResult(base_url="http://example.com")
        conn = ChatbotConnector(config, discovery, timeout=60.0)
        assert conn.client is not None
        assert conn.discovery.base_url == "http://example.com"

    def test_build_headers_with_csrf(self):
        from aegis.connectors.chatbot import ChatbotConnector
        from aegis.discovery.endpoint import DiscoveryResult
        config = TargetConfig(provider="chatbot")
        discovery = DiscoveryResult(csrf_token="test-csrf-token")
        conn = ChatbotConnector(config, discovery)
        headers = conn._build_headers()
        assert headers["X-CSRF-TOKEN"] == "test-csrf-token"

    def test_build_headers_without_csrf(self):
        from aegis.connectors.chatbot import ChatbotConnector
        from aegis.discovery.endpoint import DiscoveryResult
        config = TargetConfig(provider="chatbot")
        discovery = DiscoveryResult()
        conn = ChatbotConnector(config, discovery)
        headers = conn._build_headers()
        assert "X-CSRF-TOKEN" not in headers

    def test_build_cookies_with_auth(self):
        from aegis.connectors.chatbot import ChatbotConnector
        from aegis.discovery.endpoint import DiscoveryResult
        config = TargetConfig(provider="chatbot")
        discovery = DiscoveryResult(access_token="jwt123", csrf_token="csrf456")
        conn = ChatbotConnector(config, discovery)
        cookies = conn._build_cookies()
        assert cookies["access_token_cookie"] == "jwt123"
        assert cookies["csrf_access_token"] == "csrf456"
