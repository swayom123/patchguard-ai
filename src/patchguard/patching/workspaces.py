"""Materialize a verified patch in a separate, PatchGuard-owned review workspace."""

import os
import re
import shutil
import stat
import tempfile
from hashlib import sha256
from pathlib import Path, PurePosixPath

from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.domain.enums import PatchStatus
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.storage.models import (
    PatchWorkspace,
    Repository,
    SecurityFinding,
    SecurityPatch,
    utc_now,
)
from patchguard.verification.service import PatchVerificationService

_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".tox"}
_SECRET_FILE = re.compile(
    r"(?i)^(?:\.env(?:\..*)?|id_rsa(?:\..*)?|id_ed25519(?:\..*)?|"
    r"credentials?\.(?:json|ya?ml|toml|ini)|secrets?\.(?:json|ya?ml|toml|ini)|"
    r".*\.(?:pem|key|p12|pfx|jks))$"
)
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)\b(?:[A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|token|password)"
    rb"|api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{8,}[\"']"
)
_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


class PatchWorkspaceError(ValueError):
    """The verified patch cannot safely be materialized for review."""


class PatchWorkspaceService:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        *,
        workspace_root: Path | None,
        max_files: int,
        max_workspace_bytes: int,
        max_source_file_bytes: int,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._workspace_root = workspace_root
        self._max_files = max_files
        self._max_workspace_bytes = max_workspace_bytes
        self._max_source_file_bytes = max_source_file_bytes

    def create(self, patch_id: str) -> PatchWorkspace | None:
        patch = self._session.get(SecurityPatch, patch_id)
        if patch is None:
            return None
        existing = self._session.scalar(
            select(PatchWorkspace).where(PatchWorkspace.patch_id == patch.id)
        )
        if existing is not None:
            return existing
        if patch.status != PatchStatus.VERIFIED.value:
            raise PatchWorkspaceError(
                "only successfully verified patches can enter review workspaces"
            )
        if self._workspace_root is None:
            raise PatchWorkspaceError("patch workspace root is not configured")

        finding = self._session.get(SecurityFinding, patch.finding_id)
        repository = self._session.get(Repository, finding.repository_id) if finding else None
        if finding is None or repository is None:
            raise PatchWorkspaceError("patch repository is unavailable")
        try:
            source_root = self._boundary.authorize(Path(repository.path))
        except RepositoryBoundaryError as exc:
            raise PatchWorkspaceError("patch repository is no longer authorized") from exc

        workspace_root = self._workspace_root.expanduser().resolve()
        if workspace_root == source_root or workspace_root.is_relative_to(source_root):
            raise PatchWorkspaceError("workspace root must be outside the registered repository")
        try:
            workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise PatchWorkspaceError("configured workspace root is not writable") from exc
        if stat.S_IMODE(workspace_root.stat().st_mode) & 0o077:
            raise PatchWorkspaceError("configured workspace root must be private to its owner")
        final_path = workspace_root / patch.id
        if final_path.exists():
            raise PatchWorkspaceError("workspace path already exists without a database record")

        try:
            target = self._safe_target(source_root, patch.file_path)
            with target.open("rb") as source_file:
                original = source_file.read(self._max_source_file_bytes + 1)
        except (OSError, ValueError) as exc:
            raise PatchWorkspaceError("patch source is unavailable") from exc
        if len(original) > self._max_source_file_bytes:
            raise PatchWorkspaceError("patch source exceeds the configured size limit")
        if sha256(original).hexdigest() != patch.original_hash:
            raise PatchWorkspaceError("source changed after patch verification")

        try:
            with tempfile.TemporaryDirectory(prefix=f".{patch.id}-", dir=workspace_root) as stage:
                staging_path = Path(stage)
                self._copy_snapshot(source_root, staging_path)
                staged_target = self._safe_target(staging_path, patch.file_path)
                updated = PatchVerificationService._apply_diff(
                    original, patch.diff, patch.file_path
                )
                staged_target.chmod(staged_target.stat().st_mode | stat.S_IWUSR)
                staged_target.write_bytes(updated)
                os.replace(staging_path, final_path)
        except (OSError, ValueError) as exc:
            raise PatchWorkspaceError("a safe patch review workspace could not be created") from exc

        workspace = PatchWorkspace(
            patch_id=patch.id,
            repository_id=repository.id,
            workspace_path=str(final_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
            created_at=utc_now(),
        )
        self._session.add(workspace)
        try:
            self._session.commit()
        except Exception:
            self._session.rollback()
            shutil.rmtree(final_path)
            raise
        self._session.refresh(workspace)
        return workspace

    def _copy_snapshot(self, source: Path, destination: Path) -> None:
        files = 0
        total_size = 0
        source_device = source.stat().st_dev
        for directory, subdirectories, names in os.walk(source, followlinks=False):
            source_dir = Path(directory)
            target_dir = destination / source_dir.relative_to(source)
            target_dir.mkdir(parents=True, exist_ok=True)
            subdirectories[:] = [
                name
                for name in subdirectories
                if name not in _SKIP_DIRS
                and not (source_dir / name).is_symlink()
                and not (source_dir / name).is_mount()
                and (source_dir / name).stat().st_dev == source_device
            ]
            for name in names:
                source_file = source_dir / name
                if source_file.is_symlink() or not source_file.is_file():
                    continue
                resolved = source_file.resolve(strict=True)
                if (
                    not resolved.is_relative_to(source)
                    or source_file.stat().st_dev != source_device
                ):
                    continue
                if _SECRET_FILE.fullmatch(name) and name != ".env.example":
                    continue
                with resolved.open("rb") as secret_check:
                    sample = secret_check.read(min(self._max_source_file_bytes, 1_000_000))
                if _PRIVATE_KEY.search(sample) or _SECRET_ASSIGNMENT.search(sample):
                    continue

                files += 1
                if files > self._max_files:
                    raise ValueError("repository exceeds workspace file limit")
                target_file = target_dir / name
                target_file.parent.mkdir(parents=True, exist_ok=True)
                with resolved.open("rb") as source_stream, target_file.open("wb") as target_stream:
                    while chunk := source_stream.read(65_536):
                        total_size += len(chunk)
                        if total_size > self._max_workspace_bytes:
                            raise ValueError("repository exceeds workspace size limit")
                        target_stream.write(chunk)
                shutil.copystat(resolved, target_file, follow_symlinks=False)

    @staticmethod
    def _safe_target(root: Path, relative_path: str) -> Path:
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or ".." in relative.parts or "\\" in relative_path:
            raise ValueError("unsafe relative patch path")
        target = root.joinpath(*relative.parts)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("symlink patch path is not allowed")
        if not target.resolve(strict=True).is_relative_to(root):
            raise ValueError("patch path escapes workspace")
        return target
