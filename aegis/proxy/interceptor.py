"""LLM API traffic interceptor - lightweight recording proxy using httpx.

Captures request/response pairs for OpenAI and Anthropic API calls, parses
them into structured data, and supports replaying captured requests with
modified prompts.
"""

import json
import time
from dataclasses import dataclass, field

import httpx

from aegis.proxy.parser import (
    ParsedRequest,
    ParsedResponse,
    parse_anthropic_request,
    parse_anthropic_response,
    parse_openai_request,
    parse_openai_response,
)


@dataclass
class ProxySession:
    """A single captured request/response pair with parsed structure."""
    index: int = 0
    timestamp: float = field(default_factory=time.time)

    # Raw HTTP data
    request_url: str = ""
    request_method: str = "POST"
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: dict = field(default_factory=dict)

    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: dict = field(default_factory=dict)

    # Parsed / structured
    provider: str = ""  # "openai" or "anthropic"
    parsed_request: ParsedRequest | None = None
    parsed_response: ParsedResponse | None = None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "provider": self.provider,
            "request_url": self.request_url,
            "request_method": self.request_method,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_body": self.response_body,
            "parsed_request": {
                "system_prompt": self.parsed_request.system_prompt,
                "model": self.parsed_request.model,
                "messages": self.parsed_request.messages,
                "tools": self.parsed_request.tools,
            } if self.parsed_request else None,
            "parsed_response": {
                "content": self.parsed_response.content,
                "model": self.parsed_response.model,
                "input_tokens": self.parsed_response.input_tokens,
                "output_tokens": self.parsed_response.output_tokens,
                "finish_reason": self.parsed_response.finish_reason,
                "tool_calls": self.parsed_response.tool_calls,
            } if self.parsed_response else None,
        }


def _detect_provider(url: str, headers: dict[str, str]) -> str:
    """Infer the LLM provider from the request URL or headers."""
    url_lower = url.lower()
    if "api.openai.com" in url_lower or "chat/completions" in url_lower:
        return "openai"
    if "api.anthropic.com" in url_lower or "anthropic-version" in {
        k.lower() for k in headers
    }:
        return "anthropic"
    # Heuristic: check for common header patterns
    for key in headers:
        if key.lower() == "anthropic-version":
            return "anthropic"
    # Default to openai-compatible
    return "openai"


# TODO: websocket support
class LLMProxyInterceptor:
    """Lightweight LLM API traffic interceptor.

    Records request/response pairs, parses them into structured data using
    the protocol-aware parsers, and supports replaying captured requests
    with modified prompts.

    Usage:
        interceptor = LLMProxyInterceptor()

        # Record a request
        interceptor.record_request(url, headers, body)

        # After getting the response
        interceptor.record_response(status, headers, body)

        # View captured data
        history = interceptor.get_history()

        # Replay with modification
        new_response = await interceptor.replay(0, "modified prompt")
    """

    def __init__(self) -> None:
        self._history: list[ProxySession] = []
        self._pending_session: ProxySession | None = None
        self._listen_port: int | None = None

    def start(self, listen_port: int = 8080) -> None:
        """Configure the proxy listener port.

        For the MVP this just stores the port - a full MITM proxy is not
        started to keep the dependency footprint light. Use
        ``record_request`` / ``record_response`` to feed captured traffic.
        """
        self._listen_port = listen_port

    def record_request(
        self,
        url: str,
        headers: dict[str, str],
        body: dict | str | bytes,
    ) -> ProxySession:
        """Record an outgoing LLM API request.

        Returns the ProxySession (still pending a response).
        """
        if isinstance(body, (str, bytes)):
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                body = {"_raw": str(body)}

        provider = _detect_provider(url, headers)

        session = ProxySession(
            index=len(self._history),
            request_url=url,
            request_method="POST",
            request_headers=dict(headers),
            request_body=body,
            provider=provider,
        )

        # Parse the request
        if provider == "openai":
            session.parsed_request = parse_openai_request(body)
        elif provider == "anthropic":
            session.parsed_request = parse_anthropic_request(body)

        self._pending_session = session
        return session

    def record_response(
        self,
        status: int,
        headers: dict[str, str],
        body: dict | str | bytes,
    ) -> ProxySession | None:
        """Record the response for the most recent pending request.

        Returns the completed ProxySession, or None if no request was pending.
        """
        if self._pending_session is None:
            return None

        if isinstance(body, (str, bytes)):
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                body = {"_raw": str(body)}

        session = self._pending_session
        session.response_status = status
        session.response_headers = dict(headers)
        session.response_body = body

        # Parse the response
        if session.provider == "openai":
            session.parsed_response = parse_openai_response(body)
        elif session.provider == "anthropic":
            session.parsed_response = parse_anthropic_response(body)

        self._history.append(session)
        self._pending_session = None
        return session

    def get_history(self) -> list[ProxySession]:
        """Return all captured request/response pairs."""
        return list(self._history)

    def get_session(self, index: int) -> ProxySession:
        """Return a specific captured session by index.

        Raises IndexError if not found.
        """
        if index < 0 or index >= len(self._history):
            raise IndexError(f"Session index {index} out of range (0-{len(self._history) - 1})")
        return self._history[index]

    async def replay(
        self,
        index: int,
        modified_prompt: str,
    ) -> dict:
        """Replay a captured request with a modified user prompt.

        Takes the original request at *index*, replaces the last user message
        content with *modified_prompt*, and sends it to the original endpoint.

        Returns the raw response body as a dict.
        """
        session = self.get_session(index)
        body = dict(session.request_body)

        # Modify the last user message
        if session.provider == "openai":
            messages = list(body.get("messages", []))
            for i in range(len(messages) - 1, -1, -1):
                if messages[i].get("role") == "user":
                    messages[i] = dict(messages[i])
                    messages[i]["content"] = modified_prompt
                    break
            body["messages"] = messages

        elif session.provider == "anthropic":
            messages = list(body.get("messages", []))
            for i in range(len(messages) - 1, -1, -1):
                if messages[i].get("role") == "user":
                    messages[i] = dict(messages[i])
                    messages[i]["content"] = modified_prompt
                    break
            body["messages"] = messages

        # Send the modified request
        # Filter out headers that httpx manages
        headers = {
            k: v for k, v in session.request_headers.items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                session.request_url,
                json=body,
                headers=headers,
            )
            try:
                result = response.json()
            except Exception:
                result = {"_raw": response.text, "_status": response.status_code}

        # Record the replayed exchange
        self.record_request(session.request_url, session.request_headers, body)
        self.record_response(response.status_code, dict(response.headers), result)

        return result

    def clear(self) -> None:
        self._history.clear()
        self._pending_session = None
