from abc import ABC, abstractmethod

from patchguard.domain.scanning import ScannerExecutionRequest, ScannerExecutionResult


class ScannerRunner(ABC):
    @abstractmethod
    def execute(self, request: ScannerExecutionRequest) -> ScannerExecutionResult:
        """Execute one reviewed scanner request without interpreting repository commands."""
