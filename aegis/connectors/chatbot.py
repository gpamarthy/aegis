"""Generic chatbot connector for discovered web chat APIs.

Works with any chat interface discovered via endpoint auto-discovery,
including:
- JSON APIs with separate send/receive endpoints (e.g., /api/messages/send + /api/messages)
- Form-based POST APIs with direct response (e.g., POST /process with text=...)
- JWT/CSRF authenticated endpoints
"""

import asyncio
import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig
from aegis.discovery.endpoint import DiscoveryResult


class ChatbotConnector(BaseConnector):
    # TODO: handle SSE streaming responses from chatbot endpoints

    def __init__(self, config: TargetConfig, discovery: DiscoveryResult, timeout: float = 30.0):
        super().__init__(config)
        self.discovery = discovery
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    def _build_headers(self) -> dict:
        """Build request headers including CSRF token if needed."""
        headers = {}
        if self.discovery.csrf_token:
            headers["X-CSRF-TOKEN"] = self.discovery.csrf_token
        return headers

    def _build_cookies(self) -> dict:
        """Build cookies including JWT if needed."""
        cookies = {}
        if self.discovery.access_token:
            cookies["access_token_cookie"] = self.discovery.access_token
        if self.discovery.csrf_token:
            cookies["csrf_access_token"] = self.discovery.csrf_token
        return cookies

    async def _refresh_auth(self):
        """Re-fetch JWT/CSRF tokens from the landing page."""
        try:
            resp = await self.client.get(self.discovery.base_url + "/")
            for name, value in resp.cookies.items():
                if "access_token" in name:
                    self.discovery.access_token = value
                elif "csrf" in name.lower():
                    self.discovery.csrf_token = value
        except Exception:
            pass

    async def _do_send(self, prompt: str) -> httpx.Response:
        """Send a message using the discovered format (JSON or form data)."""
        d = self.discovery
        headers = self._build_headers()
        cookies = self._build_cookies()
        payload = {d.send_field: prompt}

        if d.content_type == "form":
            return await self.client.post(
                d.send_endpoint, data=payload,
                headers=headers, cookies=cookies,
            )
        else:
            headers["Content-Type"] = "application/json"
            return await self.client.post(
                d.send_endpoint, json=payload,
                headers=headers, cookies=cookies,
            )

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        return await self.send_single(last_user)

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        d = self.discovery

        try:
            # For poll-based APIs, get current message count first
            pre_count = 0
            if d.receive_endpoint and d.receive_endpoint != d.send_endpoint:
                try:
                    pre = await self.client.get(
                        d.receive_endpoint,
                        cookies=self._build_cookies(),
                    )
                    if pre.status_code == 200:
                        pre_data = pre.json()
                        if isinstance(pre_data, list):
                            pre_count = len(pre_data)
                except Exception:
                    pass

            # Send the message
            resp = await self._do_send(prompt)

            # Rate limit retry with exponential backoff
            for attempt, delay in enumerate([6, 12, 24]):
                if resp.status_code != 429:
                    break
                await asyncio.sleep(delay)
                resp = await self._do_send(prompt)

            # Auth expired - refresh and retry
            if resp.status_code in (401, 422) or "Missing cookie" in resp.text:
                await self._refresh_auth()
                resp = await self._do_send(prompt)

            if resp.status_code not in (200, 201):
                return LLMResponse(content=f"[ERROR {resp.status_code}]: {resp.text}")

            # Direct response API (response body IS the bot's reply)
            # Detect: if there's no separate receive endpoint, or the response
            # isn't JSON with a "message" status field
            if not d.receive_endpoint or d.receive_endpoint == d.send_endpoint:
                content = resp.text

                # Try to parse as JSON first
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        for key in ("content", "response", "message", "text", "answer", "reply", "output"):
                            if key in data and isinstance(data[key], str) and len(data[key]) > 2:
                                content = data[key]
                                break
                except Exception:
                    pass  # plain text response

                return LLMResponse(
                    content=content,
                    input_tokens=max(1, len(prompt) // 4),
                    output_tokens=max(1, len(content) // 4),
                    model=d.bot_name,
                )

            # Poll-based API (separate receive endpoint)
            for _ in range(12):
                await asyncio.sleep(2)
                try:
                    msgs_resp = await self.client.get(
                        d.receive_endpoint,
                        cookies=self._build_cookies(),
                    )
                    if msgs_resp.status_code != 200:
                        continue
                    msgs = msgs_resp.json()
                    if not isinstance(msgs, list):
                        continue
                    if len(msgs) > pre_count + 1:
                        bot_msgs = [
                            m for m in msgs[pre_count:]
                            if m.get(d.sender_field, "").lower() in (
                                d.bot_sender_value.lower(), "bot", "assistant", "ai"
                            )
                        ]
                        if bot_msgs:
                            content = bot_msgs[-1].get(d.response_field, "")
                            return LLMResponse(
                                content=content,
                                input_tokens=max(1, len(prompt) // 4),
                                output_tokens=max(1, len(content) // 4),
                                model=d.bot_name,
                            )
                except Exception:
                    continue

            return LLMResponse(content="[No bot response received]")

        except Exception as e:
            return LLMResponse(content=f"[Connection error]: {e}")

    async def close(self):
        await self.client.aclose()
