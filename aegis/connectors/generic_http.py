import logging
from typing import Any

import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig

logger = logging.getLogger(__name__)

# Default field mapping assumes an OpenAI-compatible API
DEFAULT_REQUEST_MAPPING = {
    "messages_field": "messages",
    "prompt_field": None,  # If set, sends the last user message as a string
    "role_field": "role",  # Field name for the message role (e.g. "role" or "actor")
    "content_field": "content",  # Field name for the message text (e.g. "content" or "text")
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
    """Walk a dot-separated path into a nested dict/list structure."""
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


def _set_path(data: dict, path: str, value: Any) -> None:
    """Set a value in a nested dict/list using a dot-separated path."""
    parts = path.split(".")
    current = data
    for i, part in enumerate(parts[:-1]):
        next_part = parts[i + 1]
        
        # Determine if next part is an index (list) or key (dict)
        is_list = next_part.isdigit()
        
        if part.isdigit():
            idx = int(part)
            # This case shouldn't really happen for the first part of a dict input,
            # but for completeness:
            while len(current) <= idx:
                current.append({})
            current = current[idx]
        else:
            if part not in current or not isinstance(current[part], (dict, list)):
                current[part] = [] if is_list else {}
            current = current[part]
            
    # Final assignment
    last_part = parts[-1]
    if last_part.isdigit():
        idx = int(last_part)
        while len(current) <= idx:
            current.append(None)
        current[idx] = value
    else:
        current[last_part] = value


class GenericHTTPConnector(BaseConnector):
    """Connector for any HTTP endpoint with configurable field mapping."""

    def __init__(
        self,
        config: TargetConfig,
        request_mapping: dict[str, str] | None = None,
        response_mapping: dict[str, str] | None = None,
    ):
        super().__init__(config)
        self.endpoint = config.endpoint
        self.request_mapping = {
            **DEFAULT_REQUEST_MAPPING,
            **(config.request_mapping or {}),
            **(request_mapping or {}),
        }
        self.response_mapping = {
            **DEFAULT_RESPONSE_MAPPING,
            **(config.response_mapping or {}),
            **(response_mapping or {}),
        }
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        for k, v in self.config.headers.items():
            if not k.startswith("_aegis_"):
                headers[k] = v
        return headers

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        client = self._get_client()
        payload: dict[str, Any] = {}
        
        # 1. Map messages or prompt (supports nesting via dots)
        if self.request_mapping.get("prompt_field"):
            last_msg = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    last_msg = msg.get("content", "")
                    break
            _set_path(payload, self.request_mapping["prompt_field"], last_msg)
        else:
            # Map role/content in history if needed
            role_f = self.request_mapping.get("role_field", "role")
            cont_f = self.request_mapping.get("content_field", "content")
            
            mapped_messages = []
            for m in messages:
                mapped_messages.append({
                    role_f: m.get("role"),
                    cont_f: m.get("content")
                })
            _set_path(payload, self.request_mapping["messages_field"], mapped_messages)

        # 2. Map model name
        if self.request_mapping.get("model_field"):
            _set_path(payload, self.request_mapping["model_field"], self.config.model)

        # 3. Map max tokens
        if self.request_mapping.get("max_tokens_field"):
            _set_path(payload, self.request_mapping["max_tokens_field"], kwargs.get("max_tokens", self.config.max_tokens))

        # 4. Merge extra kwargs
        for k, v in kwargs.items():
            if k not in ("max_tokens", "temperature"):
                payload[k] = v

        try:
            # print(f"DEBUG: Sending to {self.endpoint} with params {self.config.query_params}")
            resp = await client.post(
                self.endpoint,
                json=payload,
                headers=self._build_headers(),
                params=self.config.query_params or {},
            )
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(data)
        except httpx.HTTPStatusError as exc:
            logger.error("HTTP error %s: %s", exc.response.status_code, exc.response.text[:500])
            return LLMResponse(raw={"error": exc.response.text[:500]})
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
            
            # Handle list-based content (some APIs return tokens as a list)
            if isinstance(content, list):
                content = "".join(str(x) for x in content)
            
            input_tokens = _resolve_path(data, rm.get("input_tokens_path", ""))
            output_tokens = _resolve_path(data, rm.get("output_tokens_path", ""))
            finish_reason = _resolve_path(data, rm.get("finish_reason_path", ""))
            model = _resolve_path(data, rm.get("model_path", ""))

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
