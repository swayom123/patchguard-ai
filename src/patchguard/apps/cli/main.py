import json
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from patchguard.core.config import get_settings
from patchguard.core.services import (
    RepositoryIndexService,
    RepositoryService,
    ScanService,
    profile_to_dict,
)
from patchguard.execution.docker import DockerScannerRunner
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.repository.indexer import RepositoryIndexer
from patchguard.repository.language_adapters import PythonLanguageAdapter
from patchguard.repository.scanner import LocalRepositoryScanner
from patchguard.scanners.factory import build_scanners
from patchguard.scanners.orchestrator import ScanStateError, SecurityScanOrchestrator
from patchguard.storage.database import create_database_engine, create_session_factory
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
    SecurityFinding,
    SecurityScan,
)

app = typer.Typer(help="PatchGuard AI defensive security CLI", no_args_is_help=True)


def _session_factory() -> sessionmaker[Session]:
    settings = get_settings()
    return create_session_factory(create_database_engine(settings.database_url))


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port")] = 8000,
) -> None:
    """Start the PatchGuard API."""
    uvicorn.run("patchguard.apps.api.main:app", host=host, port=port)


@app.command()
def inspect(path: Annotated[Path, typer.Argument(help="Authorized repository path")]) -> None:
    """Inspect repository metadata without persistence or execution."""
    settings = get_settings()
    try:
        authorized = RepositoryBoundary(settings.allowed_repository_roots).authorize(path)
    except RepositoryBoundaryError as exc:
        raise typer.BadParameter(str(exc)) from exc
    profile = LocalRepositoryScanner(settings.allowed_repository_roots).inspect(authorized)
    typer.echo(json.dumps(profile_to_dict(profile), indent=2, sort_keys=True))


@app.command()
def register(path: Annotated[Path, typer.Argument(help="Authorized repository path")]) -> None:
    """Register a repository without modifying it."""
    settings = get_settings()
    factory = _session_factory()
    with factory() as session:
        service = RepositoryService(
            session,
            RepositoryBoundary(settings.allowed_repository_roots),
            LocalRepositoryScanner(settings.allowed_repository_roots),
        )
        try:
            repository = service.register(path)
        except RepositoryBoundaryError as exc:
            raise typer.BadParameter(str(exc)) from exc
        typer.echo(repository.id)


@app.command()
def scan(path: Annotated[Path, typer.Argument(help="Authorized repository path")]) -> None:
    """Register a repository and create a read-only pending scan record."""
    settings = get_settings()
    factory = _session_factory()
    with factory() as session:
        repository_service = RepositoryService(
            session,
            RepositoryBoundary(settings.allowed_repository_roots),
            LocalRepositoryScanner(settings.allowed_repository_roots),
        )
        try:
            repository = repository_service.register(path)
        except RepositoryBoundaryError as exc:
            raise typer.BadParameter(str(exc)) from exc
        result = ScanService(session, settings.scan_mode).create(repository.id)
        if result is None:
            raise typer.Exit(code=1)
        typer.echo(f"{result.id} {result.status}")


@app.command("scan-status")
def scan_status(scan_id: Annotated[str, typer.Argument()]) -> None:
    """Show an existing scan record."""
    factory = _session_factory()
    with factory() as session:
        scan_record = session.get(SecurityScan, scan_id)
        if scan_record is None:
            typer.echo("scan not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"{scan_record.id} {scan_record.status} {scan_record.mode}")


@app.command("scan-run")
def scan_run(scan_id: Annotated[str, typer.Argument()]) -> None:
    """Run approved defensive scanners for a pending scan."""
    settings = get_settings()
    factory = _session_factory()
    with factory() as session:
        orchestrator = SecurityScanOrchestrator(
            session,
            RepositoryBoundary(settings.allowed_repository_roots),
            build_scanners(settings),
            DockerScannerRunner(),
        )
        try:
            result = orchestrator.run(scan_id)
        except (RepositoryBoundaryError, ScanStateError) as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        if result is None:
            typer.echo("scan not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"{result.id} {result.status}")


@app.command("scanner-runs")
def scanner_runs(scan_id: Annotated[str, typer.Argument()]) -> None:
    """List scanner execution states for a scan."""
    factory = _session_factory()
    with factory() as session:
        statement = (
            select(ScannerRun).where(ScannerRun.scan_id == scan_id).order_by(ScannerRun.started_at)
        )
        for run in session.scalars(statement):
            typer.echo(
                f"{run.scanner_name} {run.status} findings={run.findings_count} "
                f"duration_ms={run.duration_ms}"
            )


@app.command()
def findings(
    repository_id: Annotated[str | None, typer.Option()] = None,
    category: Annotated[str | None, typer.Option()] = None,
    scanner: Annotated[str | None, typer.Option()] = None,
    severity: Annotated[str | None, typer.Option()] = None,
) -> None:
    """List real persisted findings; Phase 1 normally returns none."""
    factory = _session_factory()
    with factory() as session:
        statement = select(SecurityFinding)
        if repository_id:
            statement = statement.where(SecurityFinding.repository_id == repository_id)
        if category:
            statement = statement.where(SecurityFinding.category == category)
        if scanner:
            statement = statement.where(SecurityFinding.scanner.contains(scanner))
        if severity:
            statement = statement.where(SecurityFinding.severity == severity.upper())
        records = list(session.scalars(statement))
        if not records:
            typer.echo("No confirmed findings.")
            return
        for finding in records:
            typer.echo(
                f"{finding.id} {finding.severity} {finding.title} "
                f"{finding.file_path}:{finding.line_start}"
            )


@app.command("dependencies")
def dependencies(scan_id: Annotated[str, typer.Argument()]) -> None:
    """List the static dependency inventory recorded for a scan."""
    factory = _session_factory()
    with factory() as session:
        statement = (
            select(DependencyRecord)
            .where(DependencyRecord.scan_id == scan_id)
            .order_by(DependencyRecord.manifest_path, DependencyRecord.package)
        )
        for record in session.scalars(statement):
            typer.echo(
                f"{record.package} {record.version or '*'} "
                f"{record.manifest_path}:{record.line or 1}"
            )


@app.command("finding")
def finding_detail(finding_id: Annotated[str, typer.Argument()]) -> None:
    """Show one normalized finding and its evidence sources."""
    factory = _session_factory()
    with factory() as session:
        finding = session.get(SecurityFinding, finding_id)
        if finding is None:
            typer.echo("finding not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(
            f"{finding.severity} {finding.confidence} {finding.title} "
            f"{finding.file_path}:{finding.line_start} {finding.cwe_id or 'CWE-unknown'}"
        )
        statement = (
            select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.created_at)
        )
        for evidence in session.scalars(statement):
            typer.echo(f"- {evidence.scanner} {evidence.rule_id}: {evidence.summary}")


@app.command("repositories")
def repositories() -> None:
    """List registered repositories."""
    factory = _session_factory()
    with factory() as session:
        for repository in session.scalars(select(Repository)):
            typer.echo(f"{repository.id} {repository.name} {repository.path}")


@app.command("profile")
def repository_profile(repository_id: Annotated[str, typer.Argument()]) -> None:
    """Show the latest stored repository profile."""
    factory = _session_factory()
    with factory() as session:
        repository = session.get(Repository, repository_id)
        if repository is None:
            typer.echo("repository not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(json.dumps(repository.profile, indent=2, sort_keys=True))


@app.command("index")
def index_repository(repository_id: Annotated[str, typer.Argument()]) -> None:
    """Create a read-only structural index for a registered repository."""
    settings = get_settings()
    factory = _session_factory()
    with factory() as session:
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
            raise typer.BadParameter(str(exc)) from exc
        if result is None:
            typer.echo("repository not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(
            f"{result.id} {result.status} files={result.file_count} "
            f"symbols={result.symbol_count} imports={result.import_count} "
            f"calls={result.call_count} issues={result.issue_count}"
        )


@app.command("symbols")
def symbols(index_id: Annotated[str, typer.Argument()]) -> None:
    """List symbols in a repository index."""
    factory = _session_factory()
    with factory() as session:
        if session.get(RepositoryIndex, index_id) is None:
            typer.echo("index not found", err=True)
            raise typer.Exit(code=1)
        statement = (
            select(CodeSymbol)
            .where(CodeSymbol.index_id == index_id)
            .order_by(CodeSymbol.file_path, CodeSymbol.line_start)
        )
        for symbol in session.scalars(statement):
            typer.echo(
                f"{symbol.kind} {symbol.qualified_name} {symbol.file_path}:{symbol.line_start}"
            )


@app.command("imports")
def imports(index_id: Annotated[str, typer.Argument()]) -> None:
    """List imports in a repository index."""
    factory = _session_factory()
    with factory() as session:
        statement = (
            select(ImportRelation)
            .where(ImportRelation.index_id == index_id)
            .order_by(ImportRelation.file_path, ImportRelation.line)
        )
        for imported in session.scalars(statement):
            target = imported.module or ""
            if imported.imported_name:
                target = f"{target}:{imported.imported_name}"
            typer.echo(f"{target} {imported.file_path}:{imported.line}")


@app.command("calls")
def calls(index_id: Annotated[str, typer.Argument()]) -> None:
    """List conservative call relationships in a repository index."""
    factory = _session_factory()
    with factory() as session:
        statement = (
            select(CallRelation)
            .where(CallRelation.index_id == index_id)
            .order_by(CallRelation.file_path, CallRelation.line)
        )
        for call in session.scalars(statement):
            resolution = call.resolved_symbol_key or "unresolved"
            typer.echo(
                f"{call.caller_key or '<module>'} -> {call.callee_expression} "
                f"[{resolution}] {call.file_path}:{call.line}"
            )


@app.command("index-status")
def index_status(index_id: Annotated[str, typer.Argument()]) -> None:
    """Show status and counts for a repository index."""
    factory = _session_factory()
    with factory() as session:
        index_record = session.get(RepositoryIndex, index_id)
        if index_record is None:
            typer.echo("index not found", err=True)
            raise typer.Exit(code=1)
        typer.echo(
            f"{index_record.id} {index_record.status} files={index_record.file_count} "
            f"symbols={index_record.symbol_count} imports={index_record.import_count} "
            f"calls={index_record.call_count} issues={index_record.issue_count}"
        )


@app.command("index-issues")
def index_issues(index_id: Annotated[str, typer.Argument()]) -> None:
    """List explicit parse and language-support issues for an index."""
    factory = _session_factory()
    with factory() as session:
        statement = (
            select(IndexParseIssue)
            .where(IndexParseIssue.index_id == index_id)
            .order_by(IndexParseIssue.file_path, IndexParseIssue.line)
        )
        for issue in session.scalars(statement):
            location = f":{issue.line}" if issue.line is not None else ""
            typer.echo(f"{issue.kind} {issue.file_path}{location} {issue.message}")
