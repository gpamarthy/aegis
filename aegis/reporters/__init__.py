import abc
from aegis.core.findings import ScanResult
from aegis.reporters.compliance import ComplianceMapper
from aegis.reporters.html_reporter import HTMLReporter
from aegis.reporters.json_reporter import JSONReporter
from aegis.reporters.sarif_reporter import SARIFReporter


class BaseReporter(abc.ABC):
    @abc.abstractmethod
    def generate(self, result: ScanResult, output_path: str) -> str:
        ...


__all__ = [
    "BaseReporter",
    "ComplianceMapper",
    "HTMLReporter",
    "JSONReporter",
    "SARIFReporter",
]
