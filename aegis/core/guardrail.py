from dataclasses import dataclass, field


@dataclass
class GuardrailAssessment:
    """Structured result of a guardrail strength assessment scan.

    Captures how strongly an AI system resists adversarial probes across
    multiple difficulty levels, along with detailed per-probe results.
    """

    resistance_score: float = 0.0         # 0.0 (no defense) to 1.0 (impenetrable)
    deflection_pattern: str = "none"      # "none", "flat_refusal", "polite_refusal", "topic_redirect", "random_content", "mixed"
    bypass_difficulty: str = "trivial"    # "trivial", "easy", "moderate", "hard", "very_hard"
    consistency_score: float = 0.0        # How consistent are refusals (0-1)
    total_probes: int = 0
    successful_probes: int = 0
    refusal_count: int = 0
    deflection_count: int = 0
    partial_leak_count: int = 0
    probe_results: list[dict] = field(default_factory=list)  # per-probe details

    def to_dict(self) -> dict:
        return {
            "resistance_score": round(self.resistance_score, 4),
            "deflection_pattern": self.deflection_pattern,
            "bypass_difficulty": self.bypass_difficulty,
            "consistency_score": round(self.consistency_score, 4),
            "total_probes": self.total_probes,
            "successful_probes": self.successful_probes,
            "refusal_count": self.refusal_count,
            "deflection_count": self.deflection_count,
            "partial_leak_count": self.partial_leak_count,
            "probe_results": self.probe_results,
        }
