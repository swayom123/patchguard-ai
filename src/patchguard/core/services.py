from dataclasses import asdict
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.core.interfaces import RepositoryProfile, RepositoryScanner
from patchguard.domain.enums import ScanMode, ScanStatus
from patchguard.domain.intelligence import IndexStatus
from patchguard.repository.boundary import RepositoryBoundary
from patchguard.repository.indexer import RepositoryIndexer, RepositoryIndexLimitError
from patchguard.storage.models import (
    CallRelation,
    CodeSymbol,
    ImportRelation,
    IndexedFile,
    IndexParseIssue,
    Repository,
    RepositoryIndex,
    SecurityScan,
    utc_now,
)

logger = structlog.get_logger(__name__)


def profile_to_dict(profile: RepositoryProfile) -> dict[str, Any]:
    return {
        "languages": list(profile.languages),
        "frameworks": list(profile.frameworks),
        "package_managers": list(profile.package_managers),
        "dependency_files": list(profile.dependency_files),
        "test_frameworks": list(profile.test_frameworks),
        "build_commands": [list(command) for command in profile.build_commands],
        "test_commands": [list(command) for command in profile.test_commands],
        "security_tools": list(profile.security_tools),
        "source_directories": list(profile.source_directories),
        "config_files": list(profile.config_files),
        "container_files": list(profile.container_files),
        "ci_files": list(profile.ci_files),
        "infrastructure_files": list(profile.infrastructure_files),
        "build_systems": list(profile.build_systems),
        "metadata": profile.metadata,
    }


class RepositoryService:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        scanner: RepositoryScanner,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._scanner = scanner

    def register(self, requested_path: Path) -> Repository:
        path = self._boundary.authorize(requested_path)
        profile = self._scanner.inspect(path)
        default_branch = profile.metadata.get("default_branch")
        commit_hash = profile.metadata.get("commit_hash")
        existing = self._session.scalar(select(Repository).where(Repository.path == str(path)))
        if existing is not None:
            existing.profile = profile_to_dict(profile)
            existing.default_branch = default_branch if isinstance(default_branch, str) else None
            existing.commit_hash = commit_hash if isinstance(commit_hash, str) else None
            self._session.commit()
            self._session.refresh(existing)
            logger.info("repository_profile_refreshed", repository_id=existing.id)
            return existing
        repository = Repository(
            path=str(path),
            name=path.name,
            profile=profile_to_dict(profile),
            read_only=True,
            default_branch=default_branch if isinstance(default_branch, str) else None,
            commit_hash=commit_hash if isinstance(commit_hash, str) else None,
        )
        self._session.add(repository)
        self._session.commit()
        self._session.refresh(repository)
        logger.info("repository_registered", repository_id=repository.id)
        return repository


class ScanService:
    def __init__(self, session: Session, scan_mode: ScanMode) -> None:
        self._session = session
        self._scan_mode = scan_mode

    def create(self, repository_id: str) -> SecurityScan | None:
        repository = self._session.get(Repository, repository_id)
        if repository is None:
            return None
        latest_index = self._session.scalar(
            select(RepositoryIndex)
            .where(
                RepositoryIndex.repository_id == repository.id,
                RepositoryIndex.status.in_(
                    (IndexStatus.COMPLETED.value, IndexStatus.PARTIAL.value)
                ),
            )
            .order_by(RepositoryIndex.created_at.desc())
            .limit(1)
        )
        scan = SecurityScan(
            repository_id=repository.id,
            repository_index_id=latest_index.id if latest_index else None,
            repository_commit=repository.commit_hash,
            status=ScanStatus.PENDING.value,
            mode=self._scan_mode.value,
        )
        self._session.add(scan)
        self._session.commit()
        self._session.refresh(scan)
        logger.info("scan_record_created", scan_id=scan.id, repository_id=repository.id)
        return scan


class RepositoryIndexService:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        indexer: RepositoryIndexer,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._indexer = indexer

    def create(self, repository_id: str) -> RepositoryIndex | None:
        repository = self._session.get(Repository, repository_id)
        if repository is None:
            return None
        path = self._boundary.authorize(Path(repository.path))
        index_record = RepositoryIndex(
            repository_id=repository.id,
            repository_commit=repository.commit_hash,
            status=IndexStatus.RUNNING.value,
        )
        self._session.add(index_record)
        self._session.commit()
        self._session.refresh(index_record)
        try:
            result = self._indexer.index(path)
        except RepositoryIndexLimitError:
            index_record.status = IndexStatus.FAILED.value
            index_record.failure_reason = "repository exceeds configured indexing limits"
            index_record.completed_at = utc_now()
            self._session.commit()
            self._session.refresh(index_record)
            return index_record

        for file in result.files:
            self._session.add(
                IndexedFile(
                    index_id=index_record.id,
                    path=file.path,
                    language=file.language,
                    sha256=file.sha256,
                    size_bytes=file.size_bytes,
                )
            )
            for symbol in file.symbols:
                self._session.add(
                    CodeSymbol(
                        index_id=index_record.id,
                        symbol_key=symbol.key,
                        parent_key=symbol.parent_key,
                        name=symbol.name,
                        qualified_name=symbol.qualified_name,
                        kind=symbol.kind.value,
                        file_path=symbol.file_path,
                        line_start=symbol.line_start,
                        line_end=symbol.line_end,
                        column_start=symbol.column_start,
                        is_public=symbol.is_public,
                        control_flow=asdict(symbol.control_flow),
                    )
                )
            for imported in file.imports:
                self._session.add(
                    ImportRelation(
                        index_id=index_record.id,
                        file_path=imported.file_path,
                        module=imported.module,
                        imported_name=imported.imported_name,
                        alias=imported.alias,
                        level=imported.level,
                        line=imported.line,
                        resolved_file_path=imported.resolved_file_path,
                    )
                )
            for call in file.calls:
                self._session.add(
                    CallRelation(
                        index_id=index_record.id,
                        file_path=call.file_path,
                        caller_key=call.caller_key,
                        callee_expression=call.callee_expression,
                        resolved_symbol_key=call.resolved_symbol_key,
                        line=call.line,
                        column=call.column,
                    )
                )
            for issue in file.issues:
                self._session.add(
                    IndexParseIssue(
                        index_id=index_record.id,
                        file_path=issue.file_path,
                        kind=issue.kind.value,
                        message=issue.message,
                        line=issue.line,
                    )
                )

        for issue in result.issues:
            self._session.add(
                IndexParseIssue(
                    index_id=index_record.id,
                    file_path=issue.file_path,
                    kind=issue.kind.value,
                    message=issue.message,
                    line=issue.line,
                )
            )

        index_record.file_count = len(result.files)
        index_record.symbol_count = sum(len(file.symbols) for file in result.files)
        index_record.import_count = sum(len(file.imports) for file in result.files)
        index_record.call_count = sum(len(file.calls) for file in result.files)
        index_record.issue_count = sum(len(file.issues) for file in result.files) + len(
            result.issues
        )
        index_record.status = (
            IndexStatus.PARTIAL.value if index_record.issue_count else IndexStatus.COMPLETED.value
        )
        index_record.completed_at = utc_now()
        self._session.commit()
        self._session.refresh(index_record)
        logger.info(
            "repository_index_created",
            repository_id=repository.id,
            index_id=index_record.id,
            status=index_record.status,
            file_count=index_record.file_count,
        )
        return index_record
