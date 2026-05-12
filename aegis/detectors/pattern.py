"""Regex-based detector for sensitive data leakage in LLM responses."""

import re
import yaml
import pathlib
from dataclasses import dataclass
from typing import Sequence

from aegis.detectors.base_detector import BaseDetector, DetectionResult
from aegis.core.logger import get_logger

logger = get_logger("detector.pattern")

@dataclass
class PatternMatch:
    """A single regex hit inside a response string."""
    pattern_name: str
    matched_text: str
    confidence: float

# -----------------------------------------------------------------------
# YAML Rule Engine

DEFAULT_RULES_PATH = pathlib.Path(__file__).parent.parent.parent / "rules" / "patterns.yaml"

def load_patterns_from_yaml(path: str | pathlib.Path = DEFAULT_RULES_PATH) -> dict[str, tuple[re.Pattern[str], float]]:
    """Load and compile regex patterns from a YAML rule file."""
    patterns = {}
    p = pathlib.Path(path)
    
    if not p.is_file():
        logger.warning("Rules file not found, using empty pattern set", path=str(p))
        return {}

    try:
        with open(p, "r") as f:
            data = yaml.safe_load(f)
            if not data:
                return {}
            for name, info in data.items():
                patterns[name] = (re.compile(info["regex"]), info["confidence"])
        logger.info("Loaded patterns from rules engine", count=len(patterns), path=str(p))
    except Exception as e:
        logger.error("Failed to load patterns from YAML", error=str(e), path=str(p))
        
    return patterns

_PATTERNS = load_patterns_from_yaml()

class PatternDetector(BaseDetector):
    """Scans LLM output with compiled regex patterns to surface sensitive
    data such as emails, SSNs, credit-card numbers, API keys, and more.
    """

    name: str = "pattern"

    def __init__(
        self,
        patterns: dict[str, tuple[re.Pattern[str], float]] | None = None,
    ) -> None:
        self.patterns = patterns if patterns is not None else dict(_PATTERNS)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def add_pattern(
        self,
        name: str,
        regex: str | re.Pattern[str],
        confidence: float = 0.8,
    ) -> None:
        """Register a custom detection pattern at runtime."""
        if isinstance(regex, str):
            regex = re.compile(regex)
        self.patterns[name] = (regex, confidence)

    def detect_all(self, response: str) -> list[PatternMatch]:
        """Return *every* pattern match found in *response*."""
        matches: list[PatternMatch] = []
        for name, (regex, conf) in self.patterns.items():
            for m in regex.finditer(response):
                matches.append(
                    PatternMatch(
                        pattern_name=name,
                        matched_text=m.group(),
                        confidence=conf,
                    )
                )
        return matches

    # ------------------------------------------------------------------
    # Core detection (satisfies BaseDetector contract)
    # ------------------------------------------------------------------

    def detect(
        self,
        response: str,
        payload: str = "",
        context: dict | None = None,
    ) -> DetectionResult:
        """Return a single aggregated DetectionResult.

        If *context* contains a ``"patterns"`` key (a list of pattern names),
        only those patterns are checked; otherwise all registered patterns are
        evaluated.
        """
        ctx = context or {}
        wanted: Sequence[str] | None = ctx.get("patterns")

        matches = self.detect_all(response)
        if wanted:
            matches = [m for m in matches if m.pattern_name in wanted]

        if not matches:
            return DetectionResult(
                detected=False,
                confidence=0.0,
                evidence="",
                detail="No sensitive-data patterns matched",
            )

        best = max(matches, key=lambda m: m.confidence)
        summary = "; ".join(
            f"{m.pattern_name}: {m.matched_text}" for m in matches
        )
        return DetectionResult(
            detected=True,
            confidence=best.confidence,
            evidence=summary,
            detail=f"Matched {len(matches)} pattern(s) in response",
        )
