import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig
from aegis.core.logger import get_logger

logger = get_logger("connectors.openai")

DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"


class OpenAIConnector(BaseConnector):
    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.endpoint = config.endpoint or DEFAULT_ENDPOINT
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    def _build_headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers.update(self.config.headers)
        return headers

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        client = self._get_client()
        payload: dict = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
        }

        # TODO: support streaming responses for token-by-token analysis
        if "tools" in kwargs:
            payload["tools"] = kwargs["tools"]
        if "tool_choice" in kwargs:
            payload["tool_choice"] = kwargs["tool_choice"]
        if "functions" in kwargs:
            payload["functions"] = kwargs["functions"]
        if "function_call" in kwargs:
            payload["function_call"] = kwargs["function_call"]
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]

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
            logger.error(
                "OpenAI API error",
                status_code=exc.response.status_code,
                response_text=exc.response.text[:500],
            )
            return LLMResponse(raw={"error": exc.response.text[:500]})
        except Exception as exc:
            logger.error("OpenAI request failed", error=str(exc))
            return LLMResponse()

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.send(messages)

    def _parse_response(self, data: dict) -> LLMResponse:
        try:
            choice = data["choices"][0]
            message = choice["message"]
            usage = data.get("usage", {})

            return LLMResponse(
                content=message.get("content") or "",
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                model=data.get("model", ""),
                finish_reason=choice.get("finish_reason", ""),
                raw=data,
                tool_calls=message.get("tool_calls"),
            )
        except (KeyError, IndexError) as exc:
            logger.error("Failed to parse OpenAI response", error=str(exc))
            return LLMResponse(raw=data)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
