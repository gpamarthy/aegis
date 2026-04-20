import abc

from aegis.core.findings import ScanResult


class BaseReporter(abc.ABC):
    @abc.abstractmethod
    def generate(self, result: ScanResult, output_path: str) -> str:
        ...


from aegis.reporters.compliance import ComplianceMapper
from aegis.reporters.html_reporter import HTMLReporter
from aegis.reporters.json_reporter import JSONReporter
from aegis.reporters.sarif_reporter import SARIFReporter

__all__ = [
    "BaseReporter",
    "ComplianceMapper",
    "HTMLReporter",
    "JSONReporter",
    "SARIFReporter",
]
