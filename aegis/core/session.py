import enum
import time
import uuid
from dataclasses import dataclass, field


class Role(str, enum.Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    role: Role
    content: str
    timestamp: float = field(default_factory=time.time)
    tokens: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class ConversationSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    messages: list[Message] = field(default_factory=list)
    target: str = ""
    scanner: str = ""
    created_at: float = field(default_factory=time.time)
    total_tokens: int = 0
    total_cost: float = 0.0

    def add_message(self, role: Role, content: str, tokens: int = 0, **metadata) -> Message:
        msg = Message(role=role, content=content, tokens=tokens, metadata=metadata)
        self.messages.append(msg)
        self.total_tokens += tokens
        return msg

    def get_messages_for_api(self) -> list[dict]:
        return [{"role": m.role.value, "content": m.content} for m in self.messages]

    def fork(self) -> "ConversationSession":
        new_session = ConversationSession(target=self.target, scanner=self.scanner)
        new_session.messages = [Message(role=m.role, content=m.content) for m in self.messages]
        return new_session
