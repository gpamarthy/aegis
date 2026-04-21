import enum
import time
import uuid
from pydantic import BaseModel, Field, ConfigDict


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


class ComplianceMapping(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    owasp: OWASPCategory
    eu_ai_act: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    nist_ai_600: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
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
    timestamp: float = Field(default_factory=time.time)
    scanner_name: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        """Compatibility method for legacy dictionary access."""
        data = self.model_dump()
        # Ensure enum values are used in the dict
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        if self.compliance:
            data["compliance"]["owasp"] = self.compliance.owasp.value
        # Truncate response for dictionary summary
        data["response"] = self.response[:500]
        return data


class ScanResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target: str = ""
    profile: str = "quick"
    findings: list[Finding] = Field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    duration_seconds: float = 0.0
    scanners_run: list[str] = Field(default_factory=list)
    start_time: float = Field(default_factory=time.time)
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
