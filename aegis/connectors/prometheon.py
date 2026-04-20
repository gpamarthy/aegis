"""Custom connector for Prometheon CTF - JWT-authenticated chat with CSRF."""

import asyncio
import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig


class PrometheonConnector(BaseConnector):
    """Connector for Prometheon CTF challenge.

    Auth: JWT access_token_cookie + csrf_access_token via Set-Cookie on GET /.
    Chat: POST /process with form data {text: ...} + X-CSRF-TOKEN header.
    Verify: POST /verify with form data {password: ...}.
    """

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.base_url = config.endpoint.rstrip("/")
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.access_token = ""
        self.csrf_token = ""
        self._authenticated = False

    async def _authenticate(self):
        """Get JWT + CSRF tokens from the landing page."""
        if self._authenticated:
            return
        resp = await self.client.get(self.base_url + "/")
        for cookie_name, cookie_value in resp.cookies.items():
            if cookie_name == "access_token_cookie":
                self.access_token = cookie_value
            elif cookie_name == "csrf_access_token":
                self.csrf_token = cookie_value
        self._authenticated = True

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        return await self.send_single(last_user)

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        try:
            await self._authenticate()

            resp = await self.client.post(
                f"{self.base_url}/process",
                data={"text": prompt},
                headers={"X-CSRF-TOKEN": self.csrf_token},
                cookies={
                    "access_token_cookie": self.access_token,
                    "csrf_access_token": self.csrf_token,
                },
            )

            if resp.status_code == 429:
                await asyncio.sleep(3)
                resp = await self.client.post(
                    f"{self.base_url}/process",
                    data={"text": prompt},
                    headers={"X-CSRF-TOKEN": self.csrf_token},
                    cookies={
                        "access_token_cookie": self.access_token,
                        "csrf_access_token": self.csrf_token,
                    },
                )

            # Token might have expired - re-auth
            if resp.status_code == 401 or "Missing cookie" in resp.text:
                self._authenticated = False
                await self._authenticate()
                resp = await self.client.post(
                    f"{self.base_url}/process",
                    data={"text": prompt},
                    headers={"X-CSRF-TOKEN": self.csrf_token},
                    cookies={
                        "access_token_cookie": self.access_token,
                        "csrf_access_token": self.csrf_token,
                    },
                )

            content = resp.text
            return LLMResponse(
                content=content,
                input_tokens=len(prompt.split()),
                output_tokens=len(content.split()),
                model="prometheon-ai",
            )

        except Exception as e:
            return LLMResponse(content=f"[Connection error]: {e}")

    async def verify_password(self, password: str) -> str:
        """Submit a password to /verify and return the response."""
        await self._authenticate()
        resp = await self.client.post(
            f"{self.base_url}/verify",
            data={"password": password},
            headers={"X-CSRF-TOKEN": self.csrf_token},
            cookies={
                "access_token_cookie": self.access_token,
                "csrf_access_token": self.csrf_token,
            },
        )
        return resp.text

    async def close(self):
        await self.client.aclose()
