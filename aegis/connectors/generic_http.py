import json
import logging
from typing import Any

import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig

logger = logging.getLogger(__name__)

# Default field mapping assumes an OpenAI-compatible API
DEFAULT_REQUEST_MAPPING = {
    "messages_field": "messages",
    "model_field": "model",
    "max_tokens_field": "max_tokens",
}
DEFAULT_RESPONSE_MAPPING = {
    "content_path": "choices.0.message.content",
    "input_tokens_path": "usage.prompt_tokens",
    "output_tokens_path": "usage.completion_tokens",
    "finish_reason_path": "choices.0.finish_reason",
    "model_path": "model",
}


def _resolve_path(data: dict | list, path: str) -> Any:
    """Walk a dot-separated path into a nested dict/list structure.

    Example: _resolve_path(data, "choices.0.message.content")
    """
    current: Any = data
    for key in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


class GenericHTTPConnector(BaseConnector):
    """Connector for any HTTP endpoint with configurable field mapping.

    Field mappings are stored in TargetConfig.headers under special keys
    prefixed with ``_aegis_req_`` and ``_aegis_resp_``, or can be passed
    via the ``request_mapping`` / ``response_mapping`` kwargs on the
    constructor (preferred).

    Example usage::

        config = TargetConfig(
            endpoint="https://my-llm.example.com/generate",
            provider="http",
            model="my-model",
            api_key="secret",
        )
        connector = GenericHTTPConnector(
            config,
            request_mapping={"messages_field": "prompt", "model_field": "model_name"},
            response_mapping={"content_path": "result.text"},
        )
    """

    def __init__(
        self,
        config: TargetConfig,
        request_mapping: dict[str, str] | None = None,
        response_mapping: dict[str, str] | None = None,
    ):
        super().__init__(config)
        self.endpoint = config.endpoint
        self.request_mapping = {**DEFAULT_REQUEST_MAPPING, **(request_mapping or {})}
        self.response_mapping = {**DEFAULT_RESPONSE_MAPPING, **(response_mapping or {})}
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        # Include user-provided headers, but skip internal _aegis_ keys
        for k, v in self.config.headers.items():
            if not k.startswith("_aegis_"):
                headers[k] = v
        return headers

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        client = self._get_client()

        payload: dict[str, Any] = {}
        payload[self.request_mapping["messages_field"]] = messages
        if self.request_mapping.get("model_field"):
            payload[self.request_mapping["model_field"]] = self.config.model
        if self.request_mapping.get("max_tokens_field"):
            payload[self.request_mapping["max_tokens_field"]] = kwargs.get(
                "max_tokens", self.config.max_tokens
            )

        # Merge any extra payload keys the caller wants
        for k, v in kwargs.items():
            if k not in ("max_tokens", "temperature"):
                payload[k] = v

        try:
            resp = await client.post(
                self.endpoint,
                json=payload,
                headers=self._build_headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(data)
        except httpx.HTTPStatusError as exc:
            logger.error("HTTP error %s: %s", exc.response.status_code, exc.response.text[:500])
            return LLMResponse(raw={"error": exc.response.text[:500]})
        except json.JSONDecodeError as exc:
            logger.error("Non-JSON response from %s: %s", self.endpoint, exc)
            return LLMResponse(raw={"error": "Non-JSON response"})
        except Exception as exc:
            logger.error("Generic HTTP request failed: %s", exc)
            return LLMResponse(raw={"error": str(exc)})

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.send(messages)

    def _parse_response(self, data: dict) -> LLMResponse:
        try:
            rm = self.response_mapping
            content = _resolve_path(data, rm["content_path"])
            input_tokens = _resolve_path(data, rm["input_tokens_path"])
            output_tokens = _resolve_path(data, rm["output_tokens_path"])
            finish_reason = _resolve_path(data, rm["finish_reason_path"])
            model = _resolve_path(data, rm["model_path"])

            return LLMResponse(
                content=str(content) if content is not None else "",
                input_tokens=int(input_tokens) if input_tokens is not None else 0,
                output_tokens=int(output_tokens) if output_tokens is not None else 0,
                model=str(model) if model else self.config.model,
                finish_reason=str(finish_reason) if finish_reason else "",
                raw=data,
            )
        except Exception as exc:
            logger.error("Failed to parse generic HTTP response: %s", exc)
            return LLMResponse(raw=data)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
