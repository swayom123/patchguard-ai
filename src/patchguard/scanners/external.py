import json
from abc import abstractmethod
from pathlib import Path
from typing import Any

from patchguard.domain.scanning import (
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
    ScannerExecutionRequest,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter


class JsonExternalScanner(ScannerAdapter):
    image: str | None
    command: tuple[str, ...]
    timeout_seconds: int
    output_limit_bytes: int
    success_exit_codes: tuple[int, ...] = (0,)
    rules_directory: Path | None = None

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        execution = runner.execute(
            ScannerExecutionRequest(
                scanner=self.name,
                repository=repository,
                image=self.image,
                command=self.command,
                timeout_seconds=self.timeout_seconds,
                output_limit_bytes=self.output_limit_bytes,
                rules_directory=self.rules_directory,
                success_exit_codes=self.success_exit_codes,
            )
        )
        if execution.status != ExecutionStatus.COMPLETED:
            return ScannerAdapterResult(
                scanner=self.name,
                status=execution.status,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                output_truncated=execution.output_truncated,
                failure_reason=execution.failure_reason,
            )
        try:
            payload = json.loads(execution.stdout)
            findings = tuple(self.normalize(repository, payload))
        except (json.JSONDecodeError, TypeError, ValueError, KeyError):
            return ScannerAdapterResult(
                scanner=self.name,
                status=ExecutionStatus.FAILED,
                duration_ms=execution.duration_ms,
                exit_code=execution.exit_code,
                failure_reason="scanner returned malformed JSON",
            )
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=findings,
            duration_ms=execution.duration_ms,
            exit_code=execution.exit_code,
        )

    @abstractmethod
    def normalize(self, repository: Path, payload: Any) -> list[NormalizedFinding]:
        """Normalize a decoded, untrusted scanner payload."""
