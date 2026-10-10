from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from patchguard.domain.enums import (
    Confidence,
    FindingStatus,
    PatchApplicationStatus,
    PatchStatus,
    PatchWorkspaceStatus,
    ScannerRunStatus,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from patchguard.domain.intelligence import IndexStatus


def new_id() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    path: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    default_branch: Mapped[str | None] = mapped_column(String(255))
    commit_hash: Mapped[str | None] = mapped_column(String(64))
    profile: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    read_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    scans: Mapped[list[SecurityScan]] = relationship(back_populates="repository")
    indexes: Mapped[list[RepositoryIndex]] = relationship(back_populates="repository")


class RepositoryIndex(Base):
    __tablename__ = "repository_indexes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    repository_commit: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default=IndexStatus.RUNNING.value)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    symbol_count: Mapped[int] = mapped_column(Integer, default=0)
    import_count: Mapped[int] = mapped_column(Integer, default=0)
    call_count: Mapped[int] = mapped_column(Integer, default=0)
    issue_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="indexes")
    files: Mapped[list[IndexedFile]] = relationship(back_populates="index")
    symbols: Mapped[list[CodeSymbol]] = relationship(back_populates="index")
    imports: Mapped[list[ImportRelation]] = relationship(back_populates="index")
    calls: Mapped[list[CallRelation]] = relationship(back_populates="index")
    parse_issues: Mapped[list[IndexParseIssue]] = relationship(back_populates="index")


class IndexedFile(Base):
    __tablename__ = "indexed_files"
    __table_args__ = (UniqueConstraint("index_id", "path", name="uq_indexed_file_path"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    index_id: Mapped[str] = mapped_column(
        ForeignKey("repository_indexes.id"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    index: Mapped[RepositoryIndex] = relationship(back_populates="files")


class CodeSymbol(Base):
    __tablename__ = "code_symbols"
    __table_args__ = (UniqueConstraint("index_id", "symbol_key", name="uq_index_symbol_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    index_id: Mapped[str] = mapped_column(
        ForeignKey("repository_indexes.id"), nullable=False, index=True
    )
    symbol_key: Mapped[str] = mapped_column(Text, nullable=False)
    parent_key: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    qualified_name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    column_start: Mapped[int] = mapped_column(Integer, nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False)
    control_flow: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    index: Mapped[RepositoryIndex] = relationship(back_populates="symbols")


class ImportRelation(Base):
    __tablename__ = "import_relations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    index_id: Mapped[str] = mapped_column(
        ForeignKey("repository_indexes.id"), nullable=False, index=True
    )
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    module: Mapped[str | None] = mapped_column(Text)
    imported_name: Mapped[str | None] = mapped_column(Text)
    alias: Mapped[str | None] = mapped_column(String(500))
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    resolved_file_path: Mapped[str | None] = mapped_column(Text)

    index: Mapped[RepositoryIndex] = relationship(back_populates="imports")


class CallRelation(Base):
    __tablename__ = "call_relations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    index_id: Mapped[str] = mapped_column(
        ForeignKey("repository_indexes.id"), nullable=False, index=True
    )
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    caller_key: Mapped[str | None] = mapped_column(Text)
    callee_expression: Mapped[str] = mapped_column(String(256), nullable=False)
    resolved_symbol_key: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    column: Mapped[int] = mapped_column(Integer, nullable=False)

    index: Mapped[RepositoryIndex] = relationship(back_populates="calls")


class IndexParseIssue(Base):
    __tablename__ = "index_parse_issues"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    index_id: Mapped[str] = mapped_column(
        ForeignKey("repository_indexes.id"), nullable=False, index=True
    )
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    line: Mapped[int | None] = mapped_column(Integer)

    index: Mapped[RepositoryIndex] = relationship(back_populates="parse_issues")


class SecurityScan(Base):
    __tablename__ = "security_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    repository_index_id: Mapped[str | None] = mapped_column(
        ForeignKey("repository_indexes.id"), index=True
    )
    trace_id: Mapped[str] = mapped_column(String(36), nullable=False, default=new_id)
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    repository_commit: Mapped[str | None] = mapped_column(String(64))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="scans")
    scanner_runs: Mapped[list[ScannerRun]] = relationship(back_populates="scan")
    findings: Mapped[list[SecurityFinding]] = relationship(back_populates="scan")
    dependencies: Mapped[list[DependencyRecord]] = relationship(back_populates="scan")


class DependencyRecord(Base):
    __tablename__ = "dependency_records"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "manifest_path",
            "package",
            "dependency_group",
            name="uq_dependency_observation",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("security_scans.id"), nullable=False, index=True
    )
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    package: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(255))
    manifest_path: Mapped[str] = mapped_column(Text, nullable=False)
    line: Mapped[int | None] = mapped_column(Integer)
    dependency_group: Mapped[str | None] = mapped_column(String(255))
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped[SecurityScan] = relationship(back_populates="dependencies")


class ScannerRun(Base):
    __tablename__ = "scanner_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("security_scans.id"), nullable=False, index=True
    )
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(32), default=ScannerRunStatus.PENDING.value)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    execution_mode: Mapped[str] = mapped_column(String(32), default="docker")
    execution_image: Mapped[str | None] = mapped_column(String(300))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    output_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped[SecurityScan] = relationship(back_populates="scanner_runs")


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_finding_scan_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("security_scans.id"), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    primary_rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    cwe_name: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value)
    confidence: Mapped[str] = mapped_column(String(16), default=Confidence.LOW.value)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    code_reference: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.NEW.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped[SecurityScan] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(back_populates="finding")
    patches: Mapped[list[SecurityPatch]] = relationship(back_populates="finding")
    assessments: Mapped[list[SecurityAssessment]] = relationship(back_populates="finding")
    plans: Mapped[list[SecurityPatchPlan]] = relationship(back_populates="finding")
    triage_events: Mapped[list[FindingTriageEvent]] = relationship(back_populates="finding")
    suppressions: Mapped[list[FindingSuppression]] = relationship(back_populates="finding")


class SecurityAssessment(Base):
    __tablename__ = "security_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("security_findings.id"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model_name: Mapped[str | None] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_strength: Mapped[str] = mapped_column(String(16), nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    reasoning_summary: Mapped[str] = mapped_column(Text, nullable=False)
    affected_components: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommended_fix: Mapped[str] = mapped_column(Text, nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[SecurityFinding] = relationship(back_populates="assessments")


class SecurityPatchPlan(Base):
    __tablename__ = "security_patch_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("security_findings.id"), nullable=False, index=True
    )
    files_to_modify: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    strategy: Mapped[str] = mapped_column(Text, nullable=False)
    behavioral_change: Mapped[str] = mapped_column(Text, nullable=False)
    compatibility_risks: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    tests_required: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rollback_plan: Mapped[str] = mapped_column(Text, nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[SecurityFinding] = relationship(back_populates="plans")


class FindingTriageEvent(Base):
    __tablename__ = "finding_triage_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("security_findings.id"), nullable=False, index=True
    )
    previous_status: Mapped[str] = mapped_column(String(32), nullable=False)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[SecurityFinding] = relationship(back_populates="triage_events")


class FindingSuppression(Base):
    __tablename__ = "finding_suppressions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("security_findings.id"), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[SecurityFinding] = relationship(back_populates="suppressions")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("security_findings.id"), nullable=False, index=True
    )
    scanner_run_id: Mapped[str | None] = mapped_column(ForeignKey("scanner_runs.id"), index=True)
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_reference: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[SecurityFinding] = relationship(back_populates="evidence")


class SecurityPatch(Base):
    __tablename__ = "security_patches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    original_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=PatchStatus.PROPOSED.value)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[SecurityFinding] = relationship(back_populates="patches")
    verification_runs: Mapped[list[VerificationRun]] = relationship(back_populates="patch")
    workspaces: Mapped[list[PatchWorkspace]] = relationship(back_populates="patch")


class PatchWorkspace(Base):
    __tablename__ = "patch_workspaces"
    __table_args__ = (UniqueConstraint("patch_id", name="uq_patch_workspace_patch_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    patch_id: Mapped[str] = mapped_column(
        ForeignKey("security_patches.id"), nullable=False, index=True
    )
    repository_id: Mapped[str] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=PatchWorkspaceStatus.READY_FOR_REVIEW.value
    )
    failure_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    patch: Mapped[SecurityPatch] = relationship(back_populates="workspaces")


class PatchApplication(Base):
    __tablename__ = "patch_applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    patch_id: Mapped[str] = mapped_column(
        ForeignKey("security_patches.id"), nullable=False, index=True
    )
    worktree_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    backup_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=PatchApplicationStatus.PENDING.value
    )
    failure_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    patch_id: Mapped[str] = mapped_column(ForeignKey("security_patches.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=VerificationStatus.PENDING.value)
    sandbox_kind: Mapped[str] = mapped_column(String(50), default="docker")
    network_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    patch: Mapped[SecurityPatch] = relationship(back_populates="verification_runs")
