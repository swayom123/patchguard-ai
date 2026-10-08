from abc import ABC, abstractmethod
from pathlib import Path

from patchguard.domain.scanning import ScannerAdapterResult
from patchguard.execution.runner import ScannerRunner


class ScannerAdapter(ABC):
    name: str
    execution_mode = "docker"

    @abstractmethod
    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        """Inspect an authorized repository and return normalized, evidence-backed candidates."""
