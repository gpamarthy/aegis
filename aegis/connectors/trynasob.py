"""Custom connector for TrynaSob Ransomware chat API."""

import asyncio
import httpx

from aegis.connectors.base_llm import BaseConnector, LLMResponse
from aegis.core.scan_config import TargetConfig


class TrynaSobConnector(BaseConnector):
    """Connector for the TrynaSob ransomware support chat at /api/messages/send + /api/messages."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self.base_url = config.endpoint.rstrip("/")
        self.client = httpx.AsyncClient(timeout=config.max_tokens)
        self._last_msg_count = 0

    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        return await self.send_single(last_user)

    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        try:
            # Get current message count
            pre = await self.client.get(f"{self.base_url}/api/messages")
            pre_msgs = pre.json() if pre.status_code == 200 else []
            pre_count = len(pre_msgs)

            # Send the message
            resp = await self.client.post(
                f"{self.base_url}/api/messages/send",
                json={"content": prompt},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code == 429:
                await asyncio.sleep(6)
                resp = await self.client.post(
                    f"{self.base_url}/api/messages/send",
                    json={"content": prompt},
                    headers={"Content-Type": "application/json"},
                )

            if resp.status_code != 200:
                return LLMResponse(content=f"[ERROR {resp.status_code}]: {resp.text}")

            # Poll for bot response (max 15 seconds)
            for _ in range(10):
                await asyncio.sleep(2)
                msgs_resp = await self.client.get(f"{self.base_url}/api/messages")
                if msgs_resp.status_code != 200:
                    continue
                msgs = msgs_resp.json()
                if len(msgs) > pre_count + 1:
                    bot_msgs = [m for m in msgs[pre_count:] if m.get("sender") == "Bot"]
                    if bot_msgs:
                        content = bot_msgs[-1].get("content", "")
                        return LLMResponse(
                            content=content,
                            input_tokens=len(prompt.split()),
                            output_tokens=len(content.split()),
                            model="trynasob-ai",
                        )

            return LLMResponse(content="[No bot response received]")

        except Exception as e:
            return LLMResponse(content=f"[Connection error]: {e}")

    async def close(self):
        await self.client.aclose()
