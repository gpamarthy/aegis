import abc
from dataclasses import dataclass


@dataclass
class DetectionResult:
    detected: bool
    confidence: float = 0.0
    evidence: str = ""
    detail: str = ""


class BaseDetector(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def detect(self, response: str, payload: str = "", context: dict | None = None) -> DetectionResult:
        ...
