from aegis.connectors.base_llm import BaseConnector
from aegis.core.scan_config import TargetConfig


_PROVIDERS: dict[str, type[BaseConnector]] = {}
_LOADED = False


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True

    from aegis.connectors.openai import OpenAIConnector
    from aegis.connectors.anthropic import AnthropicConnector
    from aegis.connectors.ollama import OllamaConnector
    from aegis.connectors.generic_http import GenericHTTPConnector
    from aegis.connectors.trynasob import TrynaSobConnector
    from aegis.connectors.prometheon import PrometheonConnector

    _PROVIDERS["openai"] = OpenAIConnector
    _PROVIDERS["anthropic"] = AnthropicConnector
    _PROVIDERS["ollama"] = OllamaConnector
    _PROVIDERS["http"] = GenericHTTPConnector
    _PROVIDERS["trynasob"] = TrynaSobConnector
    _PROVIDERS["prometheon"] = PrometheonConnector


def get_connector(config: TargetConfig) -> BaseConnector:
    """Return an instantiated connector for the given target config.

    Raises ``ValueError`` if the provider is not recognised.
    """
    _ensure_loaded()

    provider = config.provider.lower()
    cls = _PROVIDERS.get(provider)
    if cls is None:
        available = ", ".join(sorted(_PROVIDERS))
        raise ValueError(
            f"Unknown provider '{provider}'. Available: {available}"
        )
    return cls(config)
