from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from patchguard.domain.intelligence import DataFlow, RepositoryIndexResult


@dataclass(frozen=True, slots=True)
class RepositoryProfile:
    path: Path
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    package_managers: tuple[str, ...] = ()
    dependency_files: tuple[str, ...] = ()
    test_frameworks: tuple[str, ...] = ()
    build_commands: tuple[tuple[str, ...], ...] = ()
    test_commands: tuple[tuple[str, ...], ...] = ()
    security_tools: tuple[str, ...] = ()
    source_directories: tuple[str, ...] = ()
    config_files: tuple[str, ...] = ()
    container_files: tuple[str, ...] = ()
    ci_files: tuple[str, ...] = ()
    infrastructure_files: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class RepositoryScanner(ABC):
    @abstractmethod
    def inspect(self, repository: Path) -> RepositoryProfile:
        """Read repository metadata without executing or modifying repository content."""


FindingT = TypeVar("FindingT")


class SecurityScanner[FindingT](ABC):
    name: str

    @abstractmethod
    def scan(self, repository: Path) -> object:
        """Run an approved defensive scan in a future isolated execution environment."""

    @abstractmethod
    def normalize_findings(self, raw_result: object) -> list[FindingT]:
        """Convert tool output into normalized findings without inventing evidence."""


@dataclass(frozen=True, slots=True)
class PatchPlanRequest:
    finding_id: str
    repository_id: str


@dataclass(frozen=True, slots=True)
class PatchPlanResult:
    finding_id: str
    files_to_modify: tuple[str, ...]
    strategy: str
    behavioral_change: str
    compatibility_risks: tuple[str, ...]
    tests_required: tuple[str, ...]
    rollback_plan: str


class PatchPlanner(ABC):
    @abstractmethod
    def plan(self, request: PatchPlanRequest) -> PatchPlanResult:
        """Plan a minimal patch; implementation is deferred beyond Phase 1."""


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    patch_id: str
    repository_id: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    checks: tuple[str, ...]
    failure_reason: str | None = None


class VerificationEngine(ABC):
    @abstractmethod
    def verify(self, request: VerificationRequest) -> VerificationResult:
        """Verify in isolation using structured, approved commands only."""


ModelResponseT = TypeVar("ModelResponseT")


class ModelProvider[ModelResponseT](ABC):
    @abstractmethod
    def complete(self, *, system_instruction: str, repository_context: str) -> ModelResponseT:
        """Return typed model output; repository_context is always untrusted data."""


class TaintAnalyzer(ABC):
    @abstractmethod
    def analyze(self, repository_index: RepositoryIndexResult) -> tuple[DataFlow, ...]:
        """Return conservative source-to-sink flows; implementation is deferred."""
