import abc
from dataclasses import dataclass

from aegis.core.scan_config import TargetConfig


@dataclass
class LLMResponse:
    content: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    finish_reason: str = ""
    raw: dict | None = None
    tool_calls: list[dict] | None = None


class BaseConnector(abc.ABC):
    def __init__(self, config: TargetConfig):
        self.config = config

    @abc.abstractmethod
    async def send(self, messages: list[dict], **kwargs) -> LLMResponse:
        ...

    @abc.abstractmethod
    async def send_single(self, prompt: str, system: str | None = None) -> LLMResponse:
        ...

    async def close(self):
        pass
