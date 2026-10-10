from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from patchguard.domain.enums import (
    AssessmentClassification,
    Confidence,
    FindingStatus,
    PatchStatus,
    PatchWorkspaceStatus,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from patchguard.domain.intelligence import IndexStatus, ParseIssueKind, SymbolKind


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    read_only: bool


class RepositoryCreate(BaseModel):
    path: Path


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    path: str
    name: str
    commit_hash: str | None
    profile: dict[str, Any]
    read_only: bool
    created_at: datetime
    updated_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    repository_index_id: str | None
    trace_id: str
    status: ScanStatus
    mode: str
    repository_commit: str | None
    failure_reason: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    scan_id: str
    scanner: str
    primary_rule_id: str
    title: str
    description: str
    category: str
    cwe_id: str | None
    cwe_name: str | None
    severity: Severity
    confidence: Confidence
    file_path: str
    line_start: int | None
    line_end: int | None
    code_reference: str | None
    status: FindingStatus
    created_at: datetime


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int = Field(ge=0)


class FindingTriageRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    status: FindingStatus
    note: str = Field(min_length=3, max_length=2_000)


class FindingTriageEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    previous_status: FindingStatus
    new_status: FindingStatus
    note: str
    created_at: datetime


class FindingSuppressionRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    reason: str = Field(min_length=3, max_length=2_000)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, expires_at: datetime | None) -> datetime | None:
        if expires_at is not None and (expires_at.tzinfo is None or expires_at.utcoffset() is None):
            raise ValueError("expires_at must include a timezone")
        return expires_at.astimezone(UTC) if expires_at is not None else None


class FindingSuppressionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    reason: str
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None


class DependencyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    repository_id: str
    package: str
    version: str | None
    manifest_path: str
    line: int | None
    dependency_group: str | None
    pinned: bool
    source: str
    created_at: datetime


class RepositoryIndexResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    repository_commit: str | None
    status: IndexStatus
    file_count: int
    symbol_count: int
    import_count: int
    call_count: int
    issue_count: int
    failure_reason: str | None
    created_at: datetime
    completed_at: datetime | None


class SymbolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    index_id: str
    symbol_key: str
    parent_key: str | None
    name: str
    qualified_name: str
    kind: SymbolKind
    file_path: str
    line_start: int
    line_end: int
    column_start: int
    is_public: bool
    control_flow: dict[str, int]


class ImportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    index_id: str
    file_path: str
    module: str | None
    imported_name: str | None
    alias: str | None
    level: int
    line: int
    resolved_file_path: str | None


class CallResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    index_id: str
    file_path: str
    caller_key: str | None
    callee_expression: str
    resolved_symbol_key: str | None
    line: int
    column: int


class ParseIssueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    index_id: str
    file_path: str
    kind: ParseIssueKind
    message: str
    line: int | None


class IntelligenceResponse(BaseModel):
    index: RepositoryIndexResponse
    symbols: list[SymbolResponse]
    imports: list[ImportResponse]
    calls: list[CallResponse]
    issues: list[ParseIssueResponse]


class ScannerRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    scanner_name: str
    scanner_version: str | None
    status: str
    findings_count: int
    error_message: str | None
    execution_mode: str
    execution_image: str | None
    duration_ms: int
    exit_code: int | None
    output_truncated: bool
    started_at: datetime | None
    completed_at: datetime | None


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    scanner_run_id: str | None
    scanner: str
    rule_id: str
    kind: str
    summary: str
    source_reference: str | None
    details: dict[str, Any]
    created_at: datetime


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    provider: str
    model_name: str | None
    classification: AssessmentClassification
    severity: Severity
    confidence: Confidence
    evidence_strength: Confidence
    root_cause: str
    reasoning_summary: str
    affected_components: list[str]
    recommended_fix: str
    context_digest: str
    created_at: datetime


class PatchPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    files_to_modify: list[str]
    strategy: str
    behavioral_change: str
    compatibility_risks: list[str]
    tests_required: list[str]
    rollback_plan: str
    context_digest: str
    created_at: datetime


class PatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    file_path: str
    operation: str
    original_hash: str
    diff: str
    reason: str
    status: PatchStatus
    generated_at: datetime


class VerificationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    patch_id: str
    status: VerificationStatus
    sandbox_kind: str
    network_enabled: bool
    checks: list[dict[str, Any]]
    failure_reason: str | None
    started_at: datetime | None
    completed_at: datetime | None


class PatchWorkspaceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    patch_id: str
    repository_id: str
    workspace_path: str
    source_hash: str
    status: PatchWorkspaceStatus
    failure_reason: str | None
    created_at: datetime


class FindingDetailResponse(FindingResponse):
    evidence: list[EvidenceResponse]
    assessments: list[AssessmentResponse] = []
    patch_plans: list[PatchPlanResponse] = []
    patches: list[PatchResponse] = []
    triage_events: list[FindingTriageEventResponse] = []
    suppressions: list[FindingSuppressionResponse] = []
