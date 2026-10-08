from pathlib import Path

from sqlalchemy import func, select

from patchguard.domain.enums import Confidence, ScanMode, Severity
from patchguard.domain.scanning import (
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
    ScannerExecutionRequest,
    ScannerExecutionResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.repository.boundary import RepositoryBoundary
from patchguard.scanners.base import ScannerAdapter
from patchguard.scanners.orchestrator import SecurityScanOrchestrator
from patchguard.storage.database import create_database_engine, create_session_factory
from patchguard.storage.models import Base, Evidence, Repository, SecurityFinding, SecurityScan


class UnusedRunner(ScannerRunner):
    def execute(self, request: ScannerExecutionRequest) -> ScannerExecutionResult:
        del request
        raise AssertionError("static scanner must not invoke runner")


class StaticScanner(ScannerAdapter):
    def __init__(self, name: str, rule_id: str) -> None:
        self.name = name
        self.rule_id = rule_id

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del repository, runner
        finding = NormalizedFinding(
            scanner=self.name,
            rule_id=self.rule_id,
            title="Unsafe subprocess shell execution",
            description="A subprocess call explicitly enables shell interpretation.",
            category="command-injection",
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path="service.py",
            line_start=1,
            line_end=1,
            code_reference="service.py:1",
            evidence_summary=f"{self.name} matched a controlled rule.",
        )
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=(finding,),
        )


def test_orchestrator_deduplicates_and_preserves_scanner_evidence(tmp_path: Path) -> None:
    repository_path = tmp_path / "repo"
    repository_path.mkdir()
    (repository_path / "service.py").write_text("value = 1\n", encoding="utf-8")
    engine = create_database_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        repository = Repository(path=str(repository_path), name="repo", profile={}, read_only=True)
        session.add(repository)
        session.flush()
        scan = SecurityScan(repository_id=repository.id, mode=ScanMode.TEST.value)
        session.add(scan)
        session.commit()

        result = SecurityScanOrchestrator(
            session,
            RepositoryBoundary([tmp_path]),
            [StaticScanner("bandit", "B602"), StaticScanner("semgrep", "rule.shell")],
            UnusedRunner(),
        ).run(scan.id)

        assert result is not None
        assert result.status == "COMPLETED"
        assert session.scalar(select(func.count()).select_from(SecurityFinding)) == 1
        assert session.scalar(select(func.count()).select_from(Evidence)) == 2
        finding = session.scalar(select(SecurityFinding))
        assert finding is not None
        assert finding.scanner == "bandit,semgrep"
