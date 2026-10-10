from pathlib import Path

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.domain.enums import (
    Confidence,
    FindingStatus,
    ScannerRunStatus,
    ScanStatus,
    Severity,
)
from patchguard.domain.intelligence import IndexStatus
from patchguard.domain.scanning import (
    DependencyObservation,
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.repository.boundary import RepositoryBoundary
from patchguard.scanners.base import ScannerAdapter
from patchguard.scanners.normalization import finding_fingerprint, normalize_reported_path
from patchguard.storage.models import (
    DependencyRecord,
    Evidence,
    Repository,
    RepositoryIndex,
    ScannerRun,
    SecurityFinding,
    SecurityScan,
    utc_now,
)

logger = structlog.get_logger(__name__)


class ScanStateError(ValueError):
    """Raised when a scan cannot transition from its current state."""


class SecurityScanOrchestrator:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        scanners: list[ScannerAdapter],
        runner: ScannerRunner,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._scanners = tuple(scanners)
        self._runner = runner

    def run(self, scan_id: str) -> SecurityScan | None:
        scan = self._session.get(SecurityScan, scan_id)
        if scan is None:
            return None
        if scan.status != ScanStatus.PENDING.value:
            raise ScanStateError(f"scan cannot run from status {scan.status}")
        repository = self._session.get(Repository, scan.repository_id)
        if repository is None:
            scan.status = ScanStatus.FAILED.value
            scan.failure_reason = "registered repository is unavailable"
            scan.completed_at = utc_now()
            self._session.commit()
            return scan
        path = self._boundary.authorize(Path(repository.path))
        self._attach_latest_index(scan)
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = utc_now()
        self._session.commit()

        completed_scanners = 0
        for adapter in self._scanners:
            scanner_run = ScannerRun(
                scan_id=scan.id,
                scanner_name=adapter.name,
                status=ScannerRunStatus.RUNNING.value,
                execution_mode=adapter.execution_mode,
                execution_image=getattr(adapter, "image", None),
                started_at=utc_now(),
            )
            self._session.add(scanner_run)
            self._session.commit()
            self._session.refresh(scanner_run)
            try:
                result = adapter.scan(path, self._runner)
            except Exception:
                logger.error("scanner_adapter_failed", scan_id=scan.id, scanner=adapter.name)
                result = ScannerAdapterResult(
                    scanner=adapter.name,
                    status=ExecutionStatus.FAILED,
                    failure_reason="scanner adapter failed unexpectedly",
                )
            scanner_run.scanner_version = result.version
            scanner_run.duration_ms = result.duration_ms
            scanner_run.exit_code = result.exit_code
            scanner_run.output_truncated = result.output_truncated
            scanner_run.findings_count = len(result.findings)
            scanner_run.completed_at = utc_now()
            if result.status == ExecutionStatus.COMPLETED:
                scanner_run.status = ScannerRunStatus.COMPLETED.value
                completed_scanners += 1
                self._persist_findings(scan, scanner_run, path, result.findings)
                self._persist_dependencies(scan, result.dependencies)
            elif result.status == ExecutionStatus.SKIPPED:
                scanner_run.status = ScannerRunStatus.SKIPPED.value
                scanner_run.error_message = result.failure_reason
            else:
                scanner_run.status = ScannerRunStatus.FAILED.value
                scanner_run.error_message = result.failure_reason
            self._session.commit()

        scan.completed_at = utc_now()
        if completed_scanners:
            scan.status = ScanStatus.COMPLETED.value
            scan.failure_reason = None
        else:
            scan.status = ScanStatus.FAILED.value
            scan.failure_reason = "no scanner completed successfully"
        self._session.commit()
        self._session.refresh(scan)
        logger.info(
            "security_scan_finished",
            scan_id=scan.id,
            repository_id=scan.repository_id,
            status=scan.status,
            completed_scanners=completed_scanners,
        )
        return scan

    def _attach_latest_index(self, scan: SecurityScan) -> None:
        if scan.repository_index_id is not None:
            return
        latest = self._session.scalar(
            select(RepositoryIndex)
            .where(
                RepositoryIndex.repository_id == scan.repository_id,
                RepositoryIndex.status.in_(
                    (IndexStatus.COMPLETED.value, IndexStatus.PARTIAL.value)
                ),
            )
            .order_by(RepositoryIndex.created_at.desc())
            .limit(1)
        )
        scan.repository_index_id = latest.id if latest else None

    def _persist_findings(
        self,
        scan: SecurityScan,
        scanner_run: ScannerRun,
        repository: Path,
        findings: tuple[NormalizedFinding, ...],
    ) -> None:
        evidence_keys: set[tuple[str, str, str]] = set()
        for candidate in findings:
            normalized_path = normalize_reported_path(repository, candidate.file_path)
            if normalized_path is None or candidate.line_start < 1:
                continue
            normalized = NormalizedFinding(
                scanner=candidate.scanner,
                rule_id=candidate.rule_id,
                title=candidate.title,
                description=candidate.description,
                category=candidate.category,
                cwe_id=candidate.cwe_id,
                cwe_name=candidate.cwe_name,
                severity=candidate.severity,
                confidence=candidate.confidence,
                file_path=normalized_path,
                line_start=candidate.line_start,
                line_end=max(candidate.line_start, candidate.line_end),
                code_reference=f"{normalized_path}:{candidate.line_start}",
                evidence_summary=candidate.evidence_summary,
                evidence_details=candidate.evidence_details,
            )
            fingerprint = finding_fingerprint(normalized)
            finding = self._session.scalar(
                select(SecurityFinding).where(
                    SecurityFinding.scan_id == scan.id,
                    SecurityFinding.fingerprint == fingerprint,
                )
            )
            if finding is None:
                finding = SecurityFinding(
                    repository_id=scan.repository_id,
                    scan_id=scan.id,
                    fingerprint=fingerprint,
                    scanner=normalized.scanner,
                    primary_rule_id=normalized.rule_id,
                    title=normalized.title,
                    description=normalized.description,
                    category=normalized.category,
                    cwe_id=normalized.cwe_id,
                    cwe_name=normalized.cwe_name,
                    severity=normalized.severity.value,
                    confidence=normalized.confidence.value,
                    file_path=normalized.file_path,
                    line_start=normalized.line_start,
                    line_end=normalized.line_end,
                    code_reference=normalized.code_reference,
                    status=FindingStatus.NEW.value,
                )
                self._session.add(finding)
                self._session.flush()
            else:
                finding.scanner = self._merge_scanner(finding.scanner, normalized.scanner)
                finding.severity = self._higher_severity(finding.severity, normalized.severity)
                finding.confidence = self._higher_confidence(
                    finding.confidence, normalized.confidence
                )
            evidence_key = (finding.id, normalized.scanner, normalized.rule_id)
            if evidence_key in evidence_keys:
                continue
            evidence_keys.add(evidence_key)
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    scanner_run_id=scanner_run.id,
                    scanner=normalized.scanner,
                    rule_id=normalized.rule_id,
                    kind="scanner-rule-match",
                    summary=normalized.evidence_summary,
                    source_reference=normalized.code_reference,
                    details={
                        "severity": normalized.severity.value,
                        "confidence": normalized.confidence.value,
                        **(normalized.evidence_details or {}),
                    },
                )
            )

    def _persist_dependencies(
        self, scan: SecurityScan, dependencies: tuple[DependencyObservation, ...]
    ) -> None:
        for item in dependencies:
            existing = self._session.scalar(
                select(DependencyRecord).where(
                    DependencyRecord.scan_id == scan.id,
                    DependencyRecord.manifest_path == item.manifest_path,
                    DependencyRecord.package == item.package,
                    DependencyRecord.dependency_group == item.dependency_group,
                )
            )
            if existing is None:
                self._session.add(
                    DependencyRecord(
                        scan_id=scan.id,
                        repository_id=scan.repository_id,
                        package=item.package,
                        version=item.version,
                        manifest_path=item.manifest_path,
                        line=item.line,
                        dependency_group=item.dependency_group,
                        pinned=item.pinned,
                        source=item.source,
                    )
                )

    @staticmethod
    def _merge_scanner(existing: str, additional: str) -> str:
        return ",".join(sorted({*existing.split(","), additional}))[:100]

    @staticmethod
    def _higher_severity(existing: str, additional: Severity) -> str:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        current = Severity(existing)
        return max((current, additional), key=order.index).value

    @staticmethod
    def _higher_confidence(existing: str, additional: Confidence) -> str:
        order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
        current = Confidence(existing)
        return max((current, additional), key=order.index).value
