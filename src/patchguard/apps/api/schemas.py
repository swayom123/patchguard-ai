from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from patchguard.domain.enums import (
    AssessmentClassification,
    Confidence,
    FindingStatus,
    ScanStatus,
    Severity,
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


class FindingDetailResponse(FindingResponse):
    evidence: list[EvidenceResponse]
    assessments: list[AssessmentResponse] = []
