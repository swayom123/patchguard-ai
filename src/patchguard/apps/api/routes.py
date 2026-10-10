from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from patchguard import __version__
from patchguard.agents.patch_generation import PatchGenerationAgent, PatchGenerationError
from patchguard.agents.patch_planning import PatchPlanningAgent
from patchguard.agents.security_analysis import SecurityAnalysisAgent
from patchguard.apps.api.dependencies import get_app_settings, get_session
from patchguard.apps.api.schemas import (
    AssessmentResponse,
    CallResponse,
    DependencyResponse,
    FindingDetailResponse,
    FindingListResponse,
    FindingResponse,
    FindingSuppressionRequest,
    FindingSuppressionResponse,
    FindingTriageEventResponse,
    FindingTriageRequest,
    HealthResponse,
    ImportResponse,
    ParseIssueResponse,
    PatchPlanResponse,
    PatchResponse,
    PatchWorkspaceResponse,
    RepositoryCreate,
    RepositoryIndexResponse,
    RepositoryResponse,
    ScannerRunResponse,
    ScanResponse,
    SymbolResponse,
    VerificationRunResponse,
)
from patchguard.core.config import Settings
from patchguard.core.interfaces import VerificationRequest
from patchguard.core.services import RepositoryIndexService, RepositoryService, ScanService
from patchguard.domain.enums import Confidence, FindingStatus, Severity
from patchguard.execution.docker import DockerScannerRunner
from patchguard.findings.lifecycle import FindingLifecycleError, FindingLifecycleService
from patchguard.models.factory import build_model_provider
from patchguard.models.providers import ModelUnavailableError
from patchguard.patching.workspaces import PatchWorkspaceError, PatchWorkspaceService
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.repository.indexer import RepositoryIndexer
from patchguard.repository.language_adapters import JavaScriptLanguageAdapter, PythonLanguageAdapter
from patchguard.repository.scanner import LocalRepositoryScanner
from patchguard.scanners.factory import build_scanners
from patchguard.scanners.orchestrator import ScanStateError, SecurityScanOrchestrator
from patchguard.storage.models import (
    CallRelation,
    CodeSymbol,
    DependencyRecord,
    Evidence,
    FindingSuppression,
    FindingTriageEvent,
    ImportRelation,
    IndexParseIssue,
    PatchWorkspace,
    Repository,
    RepositoryIndex,
    ScannerRun,
    SecurityAssessment,
    SecurityFinding,
    SecurityPatch,
    SecurityPatchPlan,
    SecurityScan,
    VerificationRun,
    utc_now,
)
from patchguard.verification.service import PatchVerificationService

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health(settings: Annotated[Settings, Depends(get_app_settings)]) -> HealthResponse:
    return HealthResponse(
        status="ok", service="patchguard-ai", version=__version__, read_only=settings.read_only
    )


@router.post(
    "/repositories",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["repositories"],
)
async def register_repository(
    payload: RepositoryCreate,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> Repository:
    service = RepositoryService(
        session,
        RepositoryBoundary(settings.allowed_repository_roots),
        LocalRepositoryScanner(settings.allowed_repository_roots),
    )
    try:
        return service.register(Path(payload.path))
    except RepositoryBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="repository metadata could not be inspected",
        ) from exc


@router.get("/repositories", response_model=list[RepositoryResponse], tags=["repositories"])
async def list_repositories(
    session: Annotated[Session, Depends(get_session)],
) -> list[Repository]:
    return list(session.scalars(select(Repository).order_by(Repository.created_at.desc())))


@router.get(
    "/repositories/{repository_id}",
    response_model=RepositoryResponse,
    tags=["repositories"],
)
async def get_repository(
    repository_id: str, session: Annotated[Session, Depends(get_session)]
) -> Repository:
    repository = session.get(Repository, repository_id)
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="repository not found")
    return repository


@router.post(
    "/repositories/{repository_id}/indexes",
    response_model=RepositoryIndexResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["intelligence"],
)
async def create_repository_index(
    repository_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> RepositoryIndex:
    service = RepositoryIndexService(
        session,
        RepositoryBoundary(settings.allowed_repository_roots),
        RepositoryIndexer(
            [
                PythonLanguageAdapter(max_file_size_bytes=settings.max_source_file_bytes),
                JavaScriptLanguageAdapter(max_file_size_bytes=settings.max_source_file_bytes),
            ],
            max_files=settings.max_index_files,
        ),
    )
    try:
        result = service.create(repository_id)
    except RepositoryBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="repository not found")
    return result


@router.get("/indexes/{index_id}", response_model=RepositoryIndexResponse, tags=["intelligence"])
async def get_repository_index(
    index_id: str, session: Annotated[Session, Depends(get_session)]
) -> RepositoryIndex:
    index = session.get(RepositoryIndex, index_id)
    if index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="index not found")
    return index


@router.get(
    "/indexes/{index_id}/symbols", response_model=list[SymbolResponse], tags=["intelligence"]
)
async def list_symbols(
    index_id: str,
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CodeSymbol]:
    _require_index(session, index_id)
    return list(
        session.scalars(
            select(CodeSymbol)
            .where(CodeSymbol.index_id == index_id)
            .order_by(CodeSymbol.file_path, CodeSymbol.line_start)
            .limit(limit)
            .offset(offset)
        )
    )


@router.get(
    "/indexes/{index_id}/imports", response_model=list[ImportResponse], tags=["intelligence"]
)
async def list_imports(
    index_id: str, session: Annotated[Session, Depends(get_session)]
) -> list[ImportRelation]:
    _require_index(session, index_id)
    return list(
        session.scalars(
            select(ImportRelation)
            .where(ImportRelation.index_id == index_id)
            .order_by(ImportRelation.file_path, ImportRelation.line)
        )
    )


@router.get("/indexes/{index_id}/calls", response_model=list[CallResponse], tags=["intelligence"])
async def list_calls(
    index_id: str, session: Annotated[Session, Depends(get_session)]
) -> list[CallRelation]:
    _require_index(session, index_id)
    return list(
        session.scalars(
            select(CallRelation)
            .where(CallRelation.index_id == index_id)
            .order_by(CallRelation.file_path, CallRelation.line)
        )
    )


@router.get(
    "/indexes/{index_id}/issues", response_model=list[ParseIssueResponse], tags=["intelligence"]
)
async def list_parse_issues(
    index_id: str, session: Annotated[Session, Depends(get_session)]
) -> list[IndexParseIssue]:
    _require_index(session, index_id)
    return list(
        session.scalars(
            select(IndexParseIssue)
            .where(IndexParseIssue.index_id == index_id)
            .order_by(IndexParseIssue.file_path, IndexParseIssue.line)
        )
    )


def _require_index(session: Session, index_id: str) -> None:
    if session.get(RepositoryIndex, index_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="index not found")


@router.post(
    "/repositories/{repository_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["scans"],
)
async def create_scan(
    repository_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SecurityScan:
    scan = ScanService(session, settings.scan_mode).create(repository_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="repository not found")
    return scan


@router.get("/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
async def get_scan(scan_id: str, session: Annotated[Session, Depends(get_session)]) -> SecurityScan:
    scan = session.get(SecurityScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.post("/scans/{scan_id}/run", response_model=ScanResponse, tags=["scans"])
async def run_scan(
    scan_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SecurityScan:
    orchestrator = SecurityScanOrchestrator(
        session,
        RepositoryBoundary(settings.allowed_repository_roots),
        build_scanners(settings),
        DockerScannerRunner(),
    )
    try:
        scan = orchestrator.run(scan_id)
    except ScanStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RepositoryBoundaryError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.get(
    "/scans/{scan_id}/scanner-runs",
    response_model=list[ScannerRunResponse],
    tags=["scans"],
)
async def list_scanner_runs(
    scan_id: str, session: Annotated[Session, Depends(get_session)]
) -> list[ScannerRun]:
    if session.get(SecurityScan, scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return list(
        session.scalars(
            select(ScannerRun).where(ScannerRun.scan_id == scan_id).order_by(ScannerRun.started_at)
        )
    )


@router.get(
    "/scans/{scan_id}/dependencies",
    response_model=list[DependencyResponse],
    tags=["dependencies"],
)
async def list_dependencies(
    scan_id: str, session: Annotated[Session, Depends(get_session)]
) -> list[DependencyRecord]:
    if session.get(SecurityScan, scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return list(
        session.scalars(
            select(DependencyRecord)
            .where(DependencyRecord.scan_id == scan_id)
            .order_by(DependencyRecord.manifest_path, DependencyRecord.package)
        )
    )


@router.get("/findings", response_model=FindingListResponse, tags=["findings"])
async def list_findings(
    session: Annotated[Session, Depends(get_session)],
    repository_id: str | None = None,
    scan_id: str | None = None,
    category: str | None = None,
    scanner: str | None = None,
    cwe_id: str | None = None,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    include_suppressed: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingListResponse:
    filters = []
    if repository_id is not None:
        filters.append(SecurityFinding.repository_id == repository_id)
    if scan_id is not None:
        filters.append(SecurityFinding.scan_id == scan_id)
    if category is not None:
        filters.append(SecurityFinding.category == category)
    if scanner is not None:
        filters.append(SecurityFinding.scanner.contains(scanner))
    if cwe_id is not None:
        filters.append(SecurityFinding.cwe_id == cwe_id)
    if severity is not None:
        filters.append(SecurityFinding.severity == severity.value)
    if confidence is not None:
        filters.append(SecurityFinding.confidence == confidence.value)
    if status_filter is not None:
        filters.append(SecurityFinding.status == status_filter.value)
    if not include_suppressed:
        now = utc_now()
        active_suppressions = select(FindingSuppression.finding_id).where(
            FindingSuppression.revoked_at.is_(None),
            or_(FindingSuppression.expires_at.is_(None), FindingSuppression.expires_at > now),
        )
        filters.append(~SecurityFinding.id.in_(active_suppressions))
    statement = (
        select(SecurityFinding)
        .where(*filters)
        .order_by(SecurityFinding.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    count_statement = select(func.count()).select_from(SecurityFinding).where(*filters)
    items = [FindingResponse.model_validate(item) for item in session.scalars(statement)]
    total = session.scalar(count_statement) or 0
    return FindingListResponse(items=items, total=total)


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse, tags=["findings"])
async def get_finding(
    finding_id: str, session: Annotated[Session, Depends(get_session)]
) -> FindingDetailResponse:
    finding = session.get(SecurityFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    evidence = list(
        session.scalars(
            select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.created_at)
        )
    )
    payload = FindingResponse.model_validate(finding).model_dump()
    assessments = list(
        session.scalars(
            select(SecurityAssessment)
            .where(SecurityAssessment.finding_id == finding.id)
            .order_by(SecurityAssessment.created_at.desc())
        )
    )
    patch_plans = list(
        session.scalars(
            select(SecurityPatchPlan)
            .where(SecurityPatchPlan.finding_id == finding.id)
            .order_by(SecurityPatchPlan.created_at.desc())
        )
    )
    patches = list(
        session.scalars(
            select(SecurityPatch)
            .where(SecurityPatch.finding_id == finding.id)
            .order_by(SecurityPatch.generated_at.desc())
        )
    )
    triage_events = list(
        session.scalars(
            select(FindingTriageEvent)
            .where(FindingTriageEvent.finding_id == finding.id)
            .order_by(FindingTriageEvent.created_at.desc())
        )
    )
    suppressions = list(
        session.scalars(
            select(FindingSuppression)
            .where(FindingSuppression.finding_id == finding.id)
            .order_by(FindingSuppression.created_at.desc())
        )
    )
    return FindingDetailResponse(
        **payload,
        evidence=evidence,
        assessments=assessments,
        patch_plans=patch_plans,
        patches=patches,
        triage_events=triage_events,
        suppressions=suppressions,
    )


@router.patch(
    "/findings/{finding_id}/triage",
    response_model=FindingTriageEventResponse,
    tags=["findings"],
)
async def triage_finding(
    finding_id: str,
    payload: FindingTriageRequest,
    session: Annotated[Session, Depends(get_session)],
) -> FindingTriageEvent:
    try:
        event = FindingLifecycleService(session).triage(finding_id, payload.status, payload.note)
    except FindingLifecycleError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return event


@router.post(
    "/findings/{finding_id}/suppressions",
    response_model=FindingSuppressionResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["findings"],
)
async def suppress_finding(
    finding_id: str,
    payload: FindingSuppressionRequest,
    session: Annotated[Session, Depends(get_session)],
) -> FindingSuppression:
    try:
        suppression = FindingLifecycleService(session).suppress(
            finding_id, payload.reason, payload.expires_at
        )
    except FindingLifecycleError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
                if "expiration" in str(exc)
                else status.HTTP_409_CONFLICT
            ),
            detail=str(exc),
        ) from exc
    if suppression is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return suppression


@router.post(
    "/findings/{finding_id}/unsuppressions",
    response_model=FindingSuppressionResponse,
    tags=["findings"],
)
async def unsuppress_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> FindingSuppression:
    try:
        suppression = FindingLifecycleService(session).unsuppress(finding_id)
    except FindingLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if suppression is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return suppression


@router.post(
    "/findings/{finding_id}/patch-plans",
    response_model=PatchPlanResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["patch planning"],
)
async def plan_finding_patch(
    finding_id: str, session: Annotated[Session, Depends(get_session)]
) -> SecurityPatchPlan:
    plan = PatchPlanningAgent(session).plan(finding_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return plan


@router.post(
    "/findings/{finding_id}/patches",
    response_model=PatchResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["patch generation"],
)
async def generate_finding_patch(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SecurityPatch:
    generator = PatchGenerationAgent(
        session,
        build_model_provider(settings),
        RepositoryBoundary(settings.allowed_repository_roots),
        context_limit_chars=settings.model_context_limit_chars,
        max_source_file_bytes=settings.max_source_file_bytes,
    )
    try:
        patch = generator.generate(finding_id)
    except ModelUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except PatchGenerationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if patch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return patch


@router.post(
    "/patches/{patch_id}/verify",
    response_model=VerificationRunResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["verification"],
)
async def verify_patch(
    patch_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> VerificationRun:
    patch = session.get(SecurityPatch, patch_id)
    if patch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="patch not found")
    finding = session.get(SecurityFinding, patch.finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    verifier = PatchVerificationService(
        session,
        RepositoryBoundary(settings.allowed_repository_roots),
        DockerScannerRunner(),
        image=settings.verification_image,
        timeout_seconds=settings.verification_timeout_seconds,
        output_limit_bytes=settings.verification_output_limit_bytes,
        max_files=settings.max_index_files,
        max_workspace_bytes=settings.max_verification_workspace_bytes,
        max_source_file_bytes=settings.max_source_file_bytes,
    )
    run = verifier.verify(
        VerificationRequest(patch_id=patch.id, repository_id=finding.repository_id)
    )
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="patch not found")
    return run


@router.get(
    "/verification-runs/{run_id}",
    response_model=VerificationRunResponse,
    tags=["verification"],
)
async def get_verification_run(
    run_id: str, session: Annotated[Session, Depends(get_session)]
) -> VerificationRun:
    run = session.get(VerificationRun, run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="verification run not found"
        )
    return run


@router.post(
    "/patches/{patch_id}/workspaces",
    response_model=PatchWorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["patch workspaces"],
)
async def create_patch_workspace(
    patch_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> PatchWorkspace:
    service = PatchWorkspaceService(
        session,
        RepositoryBoundary(settings.allowed_repository_roots),
        workspace_root=settings.patch_workspace_root,
        max_files=settings.max_index_files,
        max_workspace_bytes=settings.max_verification_workspace_bytes,
        max_source_file_bytes=settings.max_source_file_bytes,
    )
    try:
        workspace = service.create(patch_id)
    except PatchWorkspaceError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="patch not found")
    return workspace


@router.get(
    "/patch-workspaces/{workspace_id}",
    response_model=PatchWorkspaceResponse,
    tags=["patch workspaces"],
)
async def get_patch_workspace(
    workspace_id: str, session: Annotated[Session, Depends(get_session)]
) -> PatchWorkspace:
    workspace = session.get(PatchWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    return workspace


@router.post("/findings/{finding_id}/analyze", response_model=AssessmentResponse, tags=["analysis"])
async def analyze_finding(
    finding_id: str,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SecurityAssessment:
    agent = SecurityAnalysisAgent(
        session,
        build_model_provider(settings),
        context_limit_chars=settings.model_context_limit_chars,
    )
    try:
        assessment = agent.analyze(finding_id)
    except ModelUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return assessment
