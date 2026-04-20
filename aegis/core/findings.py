import enum
import time
import uuid
from dataclasses import dataclass, field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, enum.Enum):
    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Sensitive Information Disclosure"
    LLM03 = "LLM03: Supply Chain Vulnerabilities"
    LLM04 = "LLM04: Data and Model Poisoning"
    LLM05 = "LLM05: Improper Output Handling"
    LLM06 = "LLM06: Excessive Agency"
    LLM07 = "LLM07: System Prompt Leakage"
    LLM08 = "LLM08: Vector and Embedding Weaknesses"
    LLM09 = "LLM09: Misinformation"
    LLM10 = "LLM10: Unbounded Consumption"


@dataclass
class ComplianceMapping:
    owasp: OWASPCategory
    eu_ai_act: list[str] = field(default_factory=list)
    nist_ai_rmf: list[str] = field(default_factory=list)
    nist_ai_600: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: OWASPCategory = OWASPCategory.LLM01
    technique: str = ""
    payload: str = ""
    response: str = ""
    evidence: str = ""
    remediation: str = ""
    compliance: ComplianceMapping | None = None
    timestamp: float = field(default_factory=time.time)
    scanner_name: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "technique": self.technique,
            "payload": self.payload,
            "response": self.response[:500],
            "evidence": self.evidence,
            "remediation": self.remediation,
            "compliance": {
                "owasp": self.compliance.owasp.value,
                "eu_ai_act": self.compliance.eu_ai_act,
                "nist_ai_rmf": self.compliance.nist_ai_rmf,
            } if self.compliance else {},
            "timestamp": self.timestamp,
            "scanner_name": self.scanner_name,
            "tokens_used": self.tokens_used,
            "cost_usd": self.cost_usd,
        }


@dataclass
class ScanResult:
    target: str = ""
    profile: str = "quick"
    findings: list[Finding] = field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    duration_seconds: float = 0.0
    scanners_run: list[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def summary(self) -> dict:
        return {
            "target": self.target,
            "profile": self.profile,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "duration_seconds": round(self.duration_seconds, 1),
            "scanners_run": self.scanners_run,
        }
