"""Explicitly promote verified patches into user-selected linked worktrees."""

import os
import re
import stat
import tempfile
from hashlib import sha256
from pathlib import Path, PurePosixPath

from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.domain.enums import PatchApplicationStatus, PatchStatus
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.storage.models import (
    PatchApplication,
    PatchWorkspace,
    Repository,
    SecurityFinding,
    SecurityPatch,
    new_id,
    utc_now,
)
from patchguard.verification.service import PatchVerificationService


class PatchApplicationError(ValueError):
    """A patch cannot safely be applied or rolled back."""


class PatchApplicationService:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        *,
        backup_root: Path | None,
        max_source_file_bytes: int,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._backup_root = backup_root
        self._max_source_file_bytes = max_source_file_bytes

    def apply(
        self, patch_id: str, worktree_path: Path, confirmation: str
    ) -> PatchApplication | None:
        patch = self._session.get(SecurityPatch, patch_id)
        if patch is None:
            return None
        if confirmation != patch.id:
            raise PatchApplicationError("confirmation must exactly match the patch ID")
        if patch.status != PatchStatus.VERIFIED.value:
            raise PatchApplicationError("only successfully verified patches can be applied")
        if (
            self._session.scalar(select(PatchWorkspace).where(PatchWorkspace.patch_id == patch.id))
            is None
        ):
            raise PatchApplicationError("create a review workspace before applying a patch")
        if self._backup_root is None:
            raise PatchApplicationError("patch workspace/backup root is not configured")

        finding = self._session.get(SecurityFinding, patch.finding_id)
        repository = self._session.get(Repository, finding.repository_id) if finding else None
        if repository is None:
            raise PatchApplicationError("patch repository is unavailable")
        try:
            registered_root = self._boundary.authorize(Path(repository.path))
            worktree = self._boundary.authorize(worktree_path)
        except RepositoryBoundaryError as exc:
            raise PatchApplicationError("repository or worktree is not authorized") from exc
        if worktree == registered_root:
            raise PatchApplicationError("the registered repository itself cannot be modified")
        self._validate_linked_worktree(worktree)

        backup_root = self._backup_root.expanduser().resolve()
        if (
            backup_root in (worktree, registered_root)
            or backup_root.is_relative_to(worktree)
            or backup_root.is_relative_to(registered_root)
        ):
            raise PatchApplicationError("backup root must be outside both repositories")
        backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_IMODE(backup_root.stat().st_mode) & 0o077:
            raise PatchApplicationError("backup root must be private to its owner")
        target = self._safe_target(worktree, patch.file_path)
        original = self._read_bounded(target)
        source_hash = sha256(original).hexdigest()
        if source_hash != patch.original_hash:
            raise PatchApplicationError("worktree source differs from the verified patch source")
        try:
            updated = PatchVerificationService._apply_diff(original, patch.diff, patch.file_path)
        except ValueError as exc:
            raise PatchApplicationError("stored patch is no longer applicable") from exc

        application_id = new_id()
        backup_directory = backup_root / "backups" / application_id
        backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        (backup_root / "backups").chmod(0o700)
        backup_directory.chmod(0o700)
        backup = backup_directory / PurePosixPath(patch.file_path)
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = backup.parent
        while directory != backup_root / "backups":
            directory.chmod(0o700)
            directory = directory.parent
        self._atomic_write(backup, original, stat.S_IMODE(target.stat().st_mode))
        application = PatchApplication(
            id=application_id,
            patch_id=patch.id,
            worktree_path=str(worktree),
            file_path=patch.file_path,
            backup_path=str(backup),
            source_hash=source_hash,
            applied_hash=sha256(updated).hexdigest(),
            status=PatchApplicationStatus.PENDING.value,
        )
        self._session.add(application)
        self._session.commit()
        try:
            # Recheck immediately before replacement to avoid overwriting concurrent edits.
            if sha256(self._read_bounded(target)).hexdigest() != source_hash:
                raise PatchApplicationError("worktree source changed during patch preparation")
            self._atomic_write(target, updated, stat.S_IMODE(target.stat().st_mode))
        except (OSError, PatchApplicationError, ValueError) as exc:
            application.status = PatchApplicationStatus.FAILED.value
            application.failure_reason = str(exc)[:500]
            application.completed_at = utc_now()
            self._session.commit()
            raise PatchApplicationError(
                "patch was not applied; inspect the retained backup"
            ) from exc

        application.status = PatchApplicationStatus.APPLIED.value
        application.completed_at = utc_now()
        patch.status = PatchStatus.APPLIED.value
        self._session.commit()
        self._session.refresh(application)
        return application

    def rollback(self, application_id: str) -> PatchApplication | None:
        application = self._session.get(PatchApplication, application_id)
        if application is None:
            return None
        if application.status != PatchApplicationStatus.APPLIED.value:
            raise PatchApplicationError("only an applied patch can be rolled back")
        try:
            worktree = self._boundary.authorize(Path(application.worktree_path))
            target = self._safe_target(worktree, application.file_path)
            backup = Path(application.backup_path).resolve(strict=True)
            if self._backup_root is None or not backup.is_relative_to(
                self._backup_root.expanduser().resolve()
            ):
                raise PatchApplicationError("backup is outside the configured private backup root")
            if not backup.is_file() or backup.is_symlink():
                raise PatchApplicationError("private backup is unavailable")
            original = self._read_bounded(backup)
            if sha256(original).hexdigest() != application.source_hash:
                raise PatchApplicationError("backup hash does not match the recorded source")
            if sha256(self._read_bounded(target)).hexdigest() != application.applied_hash:
                raise PatchApplicationError("target changed since application; refusing rollback")
            self._atomic_write(target, original, stat.S_IMODE(target.stat().st_mode))
        except (OSError, RepositoryBoundaryError, ValueError) as exc:
            if isinstance(exc, PatchApplicationError):
                raise
            raise PatchApplicationError("rollback target or backup is unavailable") from exc
        application.status = PatchApplicationStatus.ROLLED_BACK.value
        application.completed_at = utc_now()
        patch = self._session.get(SecurityPatch, application.patch_id)
        if patch is not None:
            patch.status = PatchStatus.VERIFIED.value
        self._session.commit()
        self._session.refresh(application)
        return application

    @staticmethod
    def _validate_linked_worktree(worktree: Path) -> None:
        marker = worktree / ".git"
        if marker.is_symlink() or not marker.is_file():
            raise PatchApplicationError("target must be a Git-linked worktree (.git file required)")
        try:
            first_line = marker.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, UnicodeError, IndexError) as exc:
            raise PatchApplicationError("worktree Git marker is invalid") from exc
        match = re.fullmatch(r"gitdir:\s*(.+)", first_line)
        if match is None:
            raise PatchApplicationError("target is not a linked Git worktree")
        git_dir = (worktree / match.group(1)).resolve()
        if not git_dir.is_dir() or not (git_dir / "commondir").is_file():
            raise PatchApplicationError("target is not a linked Git worktree")

    @staticmethod
    def _safe_target(root: Path, relative_path: str) -> Path:
        relative = PurePosixPath(relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or "\\" in relative_path
        ):
            raise PatchApplicationError("unsafe patch path")
        target = root.joinpath(*relative.parts)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise PatchApplicationError("symlink target paths are not allowed")
        if not target.is_file() or not target.resolve(strict=True).is_relative_to(root):
            raise PatchApplicationError("patch target is unavailable")
        return target

    def _read_bounded(self, path: Path) -> bytes:
        if path.stat().st_size > self._max_source_file_bytes:
            raise PatchApplicationError("patch source exceeds configured size limit")
        with path.open("rb") as stream:
            data = stream.read(self._max_source_file_bytes + 1)
        if len(data) > self._max_source_file_bytes:
            raise PatchApplicationError("patch source exceeds configured size limit")
        return data

    @staticmethod
    def _atomic_write(path: Path, contents: bytes, mode: int) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode | stat.S_IWUSR)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
            os.replace(temporary, path)
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # The replacement succeeded; unsupported directory fsync must not misreport it.
                pass
        finally:
            temporary.unlink(missing_ok=True)
