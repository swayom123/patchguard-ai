from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patchguard import __version__
from patchguard.agents.security_analysis import SecurityAnalysisAgent
from patchguard.apps.api.dependencies import get_app_settings, get_session
from patchguard.apps.api.schemas import (
    AssessmentResponse,
    CallResponse,
    DependencyResponse,
    FindingDetailResponse,
    FindingListResponse,
    FindingResponse,
    HealthResponse,
    ImportResponse,
    ParseIssueResponse,
    RepositoryCreate,
    RepositoryIndexResponse,
    RepositoryResponse,
    ScannerRunResponse,
    ScanResponse,
    SymbolResponse,
)
from patchguard.core.config import Settings
from patchguard.core.services import RepositoryIndexService, RepositoryService, ScanService
from patchguard.domain.enums import Confidence, Severity
from patchguard.execution.docker import DockerScannerRunner
from patchguard.models.factory import build_model_provider
from patchguard.models.providers import ModelUnavailableError
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.repository.indexer import RepositoryIndexer
from patchguard.repository.language_adapters import PythonLanguageAdapter
from patchguard.repository.scanner import LocalRepositoryScanner
from patchguard.scanners.factory import build_scanners
from patchguard.scanners.orchestrator import ScanStateError, SecurityScanOrchestrator
from patchguard.storage.models import (
    CallRelation,
    CodeSymbol,
    DependencyRecord,
    Evidence,
    ImportRelation,
    IndexParseIssue,
    Repository,
    RepositoryIndex,
    ScannerRun,
    SecurityAssessment,
    SecurityFinding,
    SecurityScan,
)

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
            [PythonLanguageAdapter(max_file_size_bytes=settings.max_source_file_bytes)],
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
    return FindingDetailResponse(**payload, evidence=evidence, assessments=assessments)


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
