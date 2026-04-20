import logging

import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


class AnthropicConnector(BaseConnector):
    """Connector for the Anthropic Messages API."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.endpoint = config.endpoint or DEFAULT_ENDPOINT
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None and self._client.is_closed:
            self._client = None
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": API_VERSION,
        }
        headers.update(self.config.headers)
        return headers

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        client = self._get_client()

        # Anthropic separates system from messages. Extract system if present.
        system_text = kwargs.pop("system", None) or ""
        filtered_messages: list[dict] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_text = msg.get("content", "")
            else:
                filtered_messages.append(msg)

        payload: dict = {
            "model": self.config.model,
            "messages": filtered_messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        if system_text:
            payload["system"] = system_text

        # Support tool use
        if "tools" in kwargs:
            payload["tools"] = kwargs["tools"]
        if "tool_choice" in kwargs:
            payload["tool_choice"] = kwargs["tool_choice"]

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
            logger.error("Anthropic HTTP error %s: %s", exc.response.status_code, exc.response.text[:500])
            return LLMResponse(raw={"error": exc.response.text[:500]})
        except Exception as exc:
            logger.error("Anthropic request failed: %s", exc)
            return LLMResponse(raw={"error": str(exc)})

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        messages: list[dict] = [{"role": "user", "content": prompt}]
        kwargs: dict = {}
        if system:
            kwargs["system"] = system
        return await self.send(messages, **kwargs)

    def _parse_response(self, data: dict) -> LLMResponse:
        try:
            content_blocks = data.get("content", [])
            text_parts: list[str] = []
            tool_calls: list[dict] = []

            for block in content_blocks:
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id", ""),
                        "type": "function",
                        "function": {
                            "name": block.get("name", ""),
                            "arguments": block.get("input", {}),
                        },
                    })

            usage = data.get("usage", {})

            return LLMResponse(
                content="\n".join(text_parts),
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
                model=data.get("model", self.config.model),
                finish_reason=data.get("stop_reason", ""),
                raw=data,
                tool_calls=tool_calls if tool_calls else None,
            )
        except (KeyError, IndexError, TypeError) as exc:
            logger.error("Failed to parse Anthropic response: %s", exc)
            return LLMResponse(raw=data)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
