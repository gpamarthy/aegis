"""Protocol-aware parser for LLM API traffic (OpenAI and Anthropic formats)."""

from dataclasses import dataclass, field

@dataclass
class ParsedRequest:
    """Structured representation of an LLM API request."""
    system_prompt: str = ""
    messages: list[dict] = field(default_factory=list)
    model: str = ""
    tools: list[dict] = field(default_factory=list)
    temperature: float | None = None
    max_tokens: int | None = None
    raw: dict = field(default_factory=dict)

@dataclass
class ParsedResponse:
    """Structured representation of an LLM API response."""
    content: str = ""
    role: str = "assistant"
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    finish_reason: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

# OpenAI format parsers

def parse_openai_request(body: dict) -> ParsedRequest:
    """Parse an OpenAI Chat Completions API request body.

    Expected format:
        {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "..."},
                {"role": "user", "content": "..."},
                ...
            ],
            "tools": [...],
            "temperature": 0.7,
            "max_tokens": 1024
        }
    """
    parsed = ParsedRequest(raw=body)

    parsed.model = body.get("model", "")
    parsed.temperature = body.get("temperature")
    parsed.max_tokens = body.get("max_tokens")
    parsed.tools = body.get("tools", [])

    messages = body.get("messages", [])
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role == "system":
            # Concatenate multiple system messages
            if parsed.system_prompt:
                parsed.system_prompt += "\n" + (content or "")
            else:
                parsed.system_prompt = content or ""
        parsed.messages.append({
            "role": role,
            "content": content,
            "name": msg.get("name"),
            "tool_call_id": msg.get("tool_call_id"),
            "tool_calls": msg.get("tool_calls"),
        })

    return parsed

def parse_openai_response(body: dict) -> ParsedResponse:
    """Parse an OpenAI Chat Completions API response body.

    Expected format:
        {
            "id": "chatcmpl-...",
            "model": "gpt-4o",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "..."},
                    "finish_reason": "stop"
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
        }
    """
    parsed = ParsedResponse(raw=body)

    parsed.model = body.get("model", "")

    # Usage
    usage = body.get("usage", {})
    parsed.input_tokens = usage.get("prompt_tokens", 0)
    parsed.output_tokens = usage.get("completion_tokens", 0)
    parsed.total_tokens = usage.get("total_tokens", 0)

    # First choice
    choices = body.get("choices", [])
    if choices:
        choice = choices[0]
        parsed.finish_reason = choice.get("finish_reason", "")
        message = choice.get("message", {})
        parsed.content = message.get("content", "") or ""
        parsed.role = message.get("role", "assistant")
        parsed.tool_calls = message.get("tool_calls", []) or []

    return parsed

# ---------------------------------------------------------------------------
# Anthropic format parsers

def parse_anthropic_request(body: dict) -> ParsedRequest:
    """Parse an Anthropic Messages API request body.

    Expected format:
        {
            "model": "claude-sonnet-4-6",
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "Hello"},
                ...
            ],
            "tools": [...],
            "temperature": 0.7,
            "max_tokens": 1024
        }
    """
    parsed = ParsedRequest(raw=body)

    parsed.model = body.get("model", "")
    parsed.temperature = body.get("temperature")
    parsed.max_tokens = body.get("max_tokens")
    parsed.tools = body.get("tools", [])

    # Anthropic puts system prompt at the top level
    system = body.get("system", "")
    if isinstance(system, list):
        # Anthropic also supports system as list of content blocks
        parts = []
        for block in system:
            if isinstance(block, dict):
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        parsed.system_prompt = "\n".join(parts)
    else:
        parsed.system_prompt = system or ""

    messages = body.get("messages", [])
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        # Anthropic content can be a string or list of content blocks
        if isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        text_parts.append(f"[tool_use: {block.get('name', '')}]")
                elif isinstance(block, str):
                    text_parts.append(block)
            content_str = "\n".join(text_parts)
        else:
            content_str = content or ""

        parsed.messages.append({
            "role": role,
            "content": content_str,
        })

    return parsed

def parse_anthropic_response(body: dict) -> ParsedResponse:
    """Parse an Anthropic Messages API response body.

    Expected format:
        {
            "id": "msg_...",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-6",
            "content": [
                {"type": "text", "text": "Hello!"},
                {"type": "tool_use", "id": "...", "name": "...", "input": {...}}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 20}
        }
    """
    parsed = ParsedResponse(raw=body)

    parsed.model = body.get("model", "")
    parsed.role = body.get("role", "assistant")
    parsed.finish_reason = body.get("stop_reason", "")

    # Usage
    usage = body.get("usage", {})
    parsed.input_tokens = usage.get("input_tokens", 0)
    parsed.output_tokens = usage.get("output_tokens", 0)
    parsed.total_tokens = parsed.input_tokens + parsed.output_tokens

    # Content blocks
    content_blocks = body.get("content", [])
    text_parts = []
    tool_calls = []

    if isinstance(content_blocks, str):
        # Simple string content
        parsed.content = content_blocks
    elif isinstance(content_blocks, list):
        for block in content_blocks:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "input": block.get("input", {}),
                    })
        parsed.content = "\n".join(text_parts)
        parsed.tool_calls = tool_calls

    return parsed
