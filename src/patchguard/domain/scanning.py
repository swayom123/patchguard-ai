from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from patchguard.domain.enums import Confidence, Severity


class ExecutionStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True)
class ScannerExecutionRequest:
    scanner: str
    repository: Path
    image: str | None
    command: tuple[str, ...]
    timeout_seconds: int
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    process_limit: int = 128
    output_limit_bytes: int = 5_000_000
    rules_directory: Path | None = None
    success_exit_codes: tuple[int, ...] = (0,)
    container_user: str = "65534:65534"


@dataclass(frozen=True, slots=True)
class ScannerExecutionResult:
    status: ExecutionStatus
    stdout: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    output_truncated: bool = False
    failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    scanner: str
    rule_id: str
    title: str
    description: str
    category: str
    cwe_id: str | None
    cwe_name: str | None
    severity: Severity
    confidence: Confidence
    file_path: str
    line_start: int
    line_end: int
    code_reference: str | None
    evidence_summary: str
    evidence_details: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class DependencyObservation:
    """A dependency observed from a manifest; no package installation is involved."""

    package: str
    version: str | None
    manifest_path: str
    line: int | None
    dependency_group: str | None
    pinned: bool
    source: str


@dataclass(frozen=True, slots=True)
class ScannerAdapterResult:
    scanner: str
    status: ExecutionStatus
    findings: tuple[NormalizedFinding, ...] = ()
    dependencies: tuple[DependencyObservation, ...] = ()
    version: str | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    output_truncated: bool = False
    failure_reason: str | None = None
