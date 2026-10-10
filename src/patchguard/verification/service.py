"""Apply proposed diffs to disposable snapshots and verify them in Docker."""

import os
import re
import tempfile
from pathlib import Path, PurePosixPath

from sqlalchemy.orm import Session

from patchguard.core.interfaces import VerificationRequest, VerificationResult
from patchguard.domain.enums import PatchStatus, VerificationStatus
from patchguard.domain.scanning import ExecutionStatus, ScannerExecutionRequest
from patchguard.execution.docker import DockerScannerRunner
from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError
from patchguard.storage.models import (
    Repository,
    SecurityFinding,
    SecurityPatch,
    VerificationRun,
    utc_now,
)

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")
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


class PatchVerificationService:
    def __init__(
        self,
        session: Session,
        boundary: RepositoryBoundary,
        runner: DockerScannerRunner,
        *,
        image: str | None,
        timeout_seconds: int,
        output_limit_bytes: int,
        max_files: int,
        max_workspace_bytes: int,
        max_source_file_bytes: int,
    ) -> None:
        self._session = session
        self._boundary = boundary
        self._runner = runner
        self._image = image
        self._timeout_seconds = timeout_seconds
        self._output_limit_bytes = output_limit_bytes
        self._max_files = max_files
        self._max_workspace_bytes = max_workspace_bytes
        self._max_source_file_bytes = max_source_file_bytes

    def verify(self, request: VerificationRequest) -> VerificationRun | None:
        patch = self._session.get(SecurityPatch, request.patch_id)
        if patch is None:
            return None
        finding = self._session.get(SecurityFinding, patch.finding_id)
        if finding is None or finding.repository_id != request.repository_id:
            return None
        repository = self._session.get(Repository, request.repository_id)
        if repository is None:
            return None

        run = VerificationRun(
            patch_id=patch.id,
            status=VerificationStatus.RUNNING.value,
            sandbox_kind="docker",
            network_enabled=False,
            checks=[],
            started_at=utc_now(),
        )
        self._session.add(run)
        self._session.commit()
        self._session.refresh(run)

        try:
            result = self._verify_snapshot(patch, repository)
        except Exception:
            result = VerificationResult(
                status=VerificationStatus.FAILED,
                verified=False,
                checks=("verification_runner",),
                failure_reason="isolated verification could not be completed",
            )

        run.status = result.status.value
        run.checks = [{"check": check} for check in result.checks]
        run.failure_reason = result.failure_reason
        run.completed_at = utc_now()
        if result.status == VerificationStatus.VERIFIED:
            patch.status = PatchStatus.VERIFIED.value
        elif result.status == VerificationStatus.FAILED:
            patch.status = PatchStatus.FAILED.value
        self._session.commit()
        self._session.refresh(run)
        return run

    def _verify_snapshot(self, patch: SecurityPatch, repository: Repository) -> VerificationResult:
        if patch.status not in {PatchStatus.PROPOSED.value, PatchStatus.FAILED.value}:
            return self._review("patch_status", "patch is not in a verifiable state")
        if not self._image:
            return self._review("verification_image", "no verification image is configured")
        uid = getattr(os, "getuid", lambda: 0)()
        gid = getattr(os, "getgid", lambda: 0)()
        if uid == 0:
            return self._review("container_user", "verification is disabled for a root host user")

        try:
            root = self._boundary.authorize(Path(repository.path))
            target = self._safe_target(root, patch.file_path)
            with target.open("rb") as source_file:
                original = source_file.read(self._max_source_file_bytes + 1)
            if len(original) > self._max_source_file_bytes:
                return self._review("source_size", "patch source exceeds the configured size limit")
        except (OSError, RepositoryBoundaryError, ValueError):
            return self._review("source_file", "patch source is unavailable or unsafe")
        from hashlib import sha256

        if sha256(original).hexdigest() != patch.original_hash:
            return self._review("source_hash", "source changed since patch generation")

        frameworks = repository.profile.get("test_frameworks", [])
        if not isinstance(frameworks, list):
            frameworks = []
        if "pytest" in frameworks:
            command: tuple[str, ...] = (
                "python",
                "-B",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp=/tmp/patchguard-pytest-tmp",
            )
        elif "unittest" in frameworks:
            command = ("python", "-B", "-m", "unittest", "discover", "-v")
        else:
            return self._review("test_framework", "no supported test framework was detected")

        try:
            with tempfile.TemporaryDirectory(prefix="patchguard-verify-") as temporary:
                workspace = Path(temporary) / "workspace"
                workspace.mkdir()
                self._copy_snapshot(root, workspace)
                staged_target = self._safe_target(workspace, patch.file_path)
                staged_target.write_bytes(self._apply_diff(original, patch.diff, patch.file_path))
                execution = self._runner.execute(
                    ScannerExecutionRequest(
                        scanner="patchguard-verification",
                        repository=workspace,
                        image=self._image,
                        command=command,
                        timeout_seconds=self._timeout_seconds,
                        cpu_limit="1.0",
                        memory_limit="1g",
                        process_limit=128,
                        output_limit_bytes=self._output_limit_bytes,
                        success_exit_codes=(0,),
                        container_user=f"{uid}:{gid}",
                    )
                )
        except (OSError, ValueError):
            return self._review("workspace", "a safe verification snapshot could not be created")

        if execution.status == ExecutionStatus.SKIPPED:
            return self._review(
                "docker", "Docker or the configured verification image is unavailable"
            )
        if execution.status == ExecutionStatus.COMPLETED:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                verified=True,
                checks=("source_hash", "patch_applied_to_snapshot", "test_command_passed"),
            )
        return VerificationResult(
            status=VerificationStatus.FAILED,
            verified=False,
            checks=("source_hash", "patch_applied_to_snapshot", "test_command_failed"),
            failure_reason=execution.failure_reason or "isolated test command failed",
        )

    def _copy_snapshot(self, source: Path, destination: Path) -> None:
        files = 0
        total_size = 0
        source_device = source.stat().st_dev
        for directory, subdirectories, names in os.walk(source, followlinks=False):
            source_dir = Path(directory)
            relative_dir = source_dir.relative_to(source)
            target_dir = destination / relative_dir
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
                if source_file.stat().st_dev != source_device:
                    continue
                resolved = source_file.resolve(strict=True)
                if not resolved.is_relative_to(source):
                    continue
                if _SECRET_FILE.search(name) and name != ".env.example":
                    continue
                with resolved.open("rb") as secret_check:
                    sample = secret_check.read(min(self._max_source_file_bytes, 1_000_000))
                if _PRIVATE_KEY.search(sample) or _SECRET_ASSIGNMENT.search(sample):
                    continue
                files += 1
                if files > self._max_files:
                    raise ValueError("repository exceeds verification snapshot limits")
                target_file = target_dir / name
                target_file.parent.mkdir(parents=True, exist_ok=True)
                with resolved.open("rb") as source_stream, target_file.open("wb") as target_stream:
                    while chunk := source_stream.read(65_536):
                        total_size += len(chunk)
                        if total_size > self._max_workspace_bytes:
                            raise ValueError("repository exceeds verification snapshot limits")
                        target_stream.write(chunk)

    @staticmethod
    def _safe_target(root: Path, relative_path: str) -> Path:
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or ".." in relative.parts or "\\" in relative_path:
            raise ValueError("unsafe relative path")
        target = root.joinpath(*relative.parts)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("symlink path is not allowed")
        if not target.resolve(strict=True).is_relative_to(root):
            raise ValueError("path escapes workspace")
        return target

    @staticmethod
    def _apply_diff(original: bytes, diff: str, relative_path: str) -> bytes:
        try:
            source_text = original.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError("source is not UTF-8") from exc
        lines = diff.splitlines()
        if len(lines) < 4 or lines[:2] != [f"--- a/{relative_path}", f"+++ b/{relative_path}"]:
            raise ValueError("patch file headers do not match")
        if any(line.startswith(("\\ ", "diff --git ", "index ")) for line in lines[2:]):
            raise ValueError("unsupported patch metadata")

        source_lines = source_text.splitlines()
        output: list[str] = []
        source_index = 0
        line_index = 2
        while line_index < len(lines):
            header = _HUNK_HEADER.fullmatch(lines[line_index])
            if header is None:
                raise ValueError("invalid unified diff hunk")
            old_start = int(header.group(1))
            old_count = int(header.group(2) or "1")
            new_start = int(header.group(3))
            new_count = int(header.group(4) or "1")
            hunk_start = old_start - 1 if old_count else old_start
            expected_new_start = new_start - 1 if new_count else new_start
            if hunk_start < source_index or hunk_start > len(source_lines):
                raise ValueError("diff hunks are out of order")
            output.extend(source_lines[source_index:hunk_start])
            if len(output) != expected_new_start:
                raise ValueError("diff new hunk location is inconsistent")
            source_index = hunk_start
            consumed = 0
            produced = 0
            line_index += 1
            while line_index < len(lines) and not lines[line_index].startswith("@@ "):
                line = lines[line_index]
                if not line:
                    raise ValueError("invalid empty diff line")
                marker, text = line[0], line[1:]
                if marker == " ":
                    if source_index >= len(source_lines) or source_lines[source_index] != text:
                        raise ValueError("diff context does not match source")
                    output.append(text)
                    source_index += 1
                    consumed += 1
                    produced += 1
                elif marker == "-":
                    if source_index >= len(source_lines) or source_lines[source_index] != text:
                        raise ValueError("diff removal does not match source")
                    source_index += 1
                    consumed += 1
                elif marker == "+":
                    output.append(text)
                    produced += 1
                else:
                    raise ValueError("invalid unified diff line")
                line_index += 1
            if consumed != old_count or produced != new_count:
                raise ValueError("diff hunk line counts do not match")
        output.extend(source_lines[source_index:])
        final_newline = source_text.endswith("\n")
        newline = "\r\n" if "\r\n" in source_text else "\n"
        updated = newline.join(output)
        if final_newline:
            updated += newline
        return updated.encode("utf-8")

    @staticmethod
    def _review(check: str, reason: str) -> VerificationResult:
        return VerificationResult(
            status=VerificationStatus.REVIEW_REQUIRED,
            verified=False,
            checks=(check,),
            failure_reason=reason,
        )
