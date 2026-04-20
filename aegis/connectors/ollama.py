import logging

import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "http://localhost:11434/api/chat"


class OllamaConnector(BaseConnector):
    """Connector for the Ollama local inference API."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.endpoint = config.endpoint or DEFAULT_ENDPOINT
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        headers.update(self.config.headers)
        return headers

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        client = self._get_client()

        payload: dict = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            },
        }

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
            logger.error("Ollama HTTP error %s: %s", exc.response.status_code, exc.response.text[:500])
            return LLMResponse(raw={"error": exc.response.text[:500]})
        except httpx.ConnectError:
            logger.error("Cannot connect to Ollama at %s - is it running?", self.endpoint)
            return LLMResponse(raw={"error": f"Connection refused: {self.endpoint}"})
        except Exception as exc:
            logger.error("Ollama request failed: %s", exc)
            return LLMResponse(raw={"error": str(exc)})

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.send(messages)

    def _parse_response(self, data: dict) -> LLMResponse:
        try:
            message = data.get("message", {})
            content = message.get("content", "")

            # FIXME: ollama doesn't report token counts on older versions, need fallback
            input_tokens = data.get("prompt_eval_count", 0) or 0
            output_tokens = data.get("eval_count", 0) or 0

            # Ollama supports tool calls in newer versions
            tool_calls = None
            if message.get("tool_calls"):
                tool_calls = [
                    {
                        "type": "function",
                        "function": {
                            "name": tc.get("function", {}).get("name", ""),
                            "arguments": tc.get("function", {}).get("arguments", {}),
                        },
                    }
                    for tc in message["tool_calls"]
                ]

            return LLMResponse(
                content=content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=data.get("model", self.config.model),
                finish_reason=data.get("done_reason", "stop") if data.get("done") else "",
                raw=data,
                tool_calls=tool_calls,
            )
        except (KeyError, IndexError, TypeError) as exc:
            logger.error("Failed to parse Ollama response: %s", exc)
            return LLMResponse(raw=data)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
