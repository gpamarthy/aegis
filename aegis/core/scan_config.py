import enum
from dataclasses import dataclass, field


class ScanProfile(str, enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    STEALTH = "stealth"


@dataclass
class TargetConfig:
    endpoint: str = ""
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    system_prompt: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.7


@dataclass
class ScanConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    profile: ScanProfile = ScanProfile.QUICK
    budget_usd: float = 5.0
    max_requests: int = 500
    concurrency: int = 5
    timeout: float = 30.0
    scanners: list[str] = field(default_factory=list)
    output_file: str = "aegis_report.html"
    output_format: str = "html"
    attacker_model: str = "gpt-4o-mini"
    attacker_api_key: str = ""
    attacker_provider: str = "openai"
    verbose: bool = False
