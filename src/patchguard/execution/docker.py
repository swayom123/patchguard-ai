import re
import shutil
import subprocess
import threading
import time
from typing import BinaryIO

from patchguard.domain.scanning import (
    ExecutionStatus,
    ScannerExecutionRequest,
    ScannerExecutionResult,
)
from patchguard.execution.runner import ScannerRunner

_IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$")
_ALLOWED_EXECUTABLES = {
    "bandit": {"bandit"},
    "semgrep": {"semgrep"},
}


class DockerScannerRunner(ScannerRunner):
    """Runs reviewed scanner commands in a resource-limited, networkless container."""

    def execute(self, request: ScannerExecutionRequest) -> ScannerExecutionResult:
        started = time.monotonic()
        docker = shutil.which("docker")
        if docker is None:
            return self._result(ExecutionStatus.SKIPPED, started, "docker is unavailable")
        if request.image is None:
            return self._result(ExecutionStatus.SKIPPED, started, "scanner image is not configured")
        if not _IMAGE_PATTERN.fullmatch(request.image):
            return self._result(ExecutionStatus.FAILED, started, "scanner image is invalid")
        allowed = _ALLOWED_EXECUTABLES.get(request.scanner, set())
        if not request.command or request.command[0] not in allowed:
            return self._result(ExecutionStatus.FAILED, started, "scanner command is not allowed")
        repository = request.repository.resolve()
        if not repository.is_dir():
            return self._result(ExecutionStatus.FAILED, started, "repository is unavailable")
        if not self._image_available(docker, request.image):
            return self._result(ExecutionStatus.SKIPPED, started, "scanner image is unavailable")

        command = [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--cpus",
            request.cpu_limit,
            "--memory",
            request.memory_limit,
            "--pids-limit",
            str(request.process_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65534:65534",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m,mode=1777",  # noqa: S108
            "--env",
            "HOME=/tmp",
            "--volume",
            f"{repository}:/workspace:ro",
        ]
        if request.rules_directory is not None:
            rules = request.rules_directory.resolve()
            if not rules.is_dir():
                return self._result(
                    ExecutionStatus.FAILED, started, "scanner rules are unavailable"
                )
            command.extend(("--volume", f"{rules}:/rules:ro"))
        command.extend((request.image, *request.command))
        return self._run(command, request, started)

    @staticmethod
    def _image_available(docker: str, image: str) -> bool:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed Docker executable and subcommand
                [docker, "image", "inspect", image],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    def _run(
        self, command: list[str], request: ScannerExecutionRequest, started: float
    ) -> ScannerExecutionResult:
        try:
            process = subprocess.Popen(  # noqa: S603 - validated structured scanner command
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError:
            return self._result(ExecutionStatus.FAILED, started, "container could not start")

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_size = [0]
        stderr_size = [0]
        readers = [
            threading.Thread(
                target=self._drain,
                args=(process.stdout, request.output_limit_bytes, stdout_chunks, stdout_size),
                daemon=True,
            ),
            threading.Thread(
                target=self._drain,
                args=(process.stderr, request.output_limit_bytes, stderr_chunks, stderr_size),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        try:
            exit_code = process.wait(timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            for reader in readers:
                reader.join(timeout=2)
            return self._result(ExecutionStatus.TIMEOUT, started, "scanner timed out")
        for reader in readers:
            reader.join(timeout=2)

        truncated = (
            stdout_size[0] > request.output_limit_bytes
            or stderr_size[0] > request.output_limit_bytes
        )
        if truncated:
            return ScannerExecutionResult(
                status=ExecutionStatus.FAILED,
                exit_code=exit_code,
                duration_ms=self._duration(started),
                output_truncated=True,
                failure_reason="scanner output exceeded configured limit",
            )
        if exit_code not in request.success_exit_codes:
            return ScannerExecutionResult(
                status=ExecutionStatus.FAILED,
                exit_code=exit_code,
                duration_ms=self._duration(started),
                failure_reason="scanner exited unsuccessfully",
            )
        return ScannerExecutionResult(
            status=ExecutionStatus.COMPLETED,
            stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            exit_code=exit_code,
            duration_ms=self._duration(started),
        )

    @staticmethod
    def _drain(
        stream: BinaryIO | None,
        limit: int,
        chunks: list[bytes],
        total: list[int],
    ) -> None:
        if stream is None:
            return
        with stream:
            while chunk := stream.read(65_536):
                total[0] += len(chunk)
                retained = sum(len(item) for item in chunks)
                if retained < limit + 1:
                    chunks.append(chunk[: limit + 1 - retained])

    @staticmethod
    def _duration(started: float) -> int:
        return int((time.monotonic() - started) * 1000)

    def _result(
        self, status: ExecutionStatus, started: float, reason: str
    ) -> ScannerExecutionResult:
        return ScannerExecutionResult(
            status=status,
            duration_ms=self._duration(started),
            failure_reason=reason,
        )
