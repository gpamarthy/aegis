import abc
from aegis.core.findings import ScanResult

class BaseReporter(abc.ABC):
    @abc.abstractmethod
    def generate(self, result: ScanResult, output_path: str) -> str:
        ...
