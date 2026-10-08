import io
import subprocess
from pathlib import Path
from typing import Any

import pytest

from patchguard.domain.scanning import ExecutionStatus, ScannerExecutionRequest
from patchguard.execution.docker import DockerScannerRunner


class FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"{}",
        stderr: bytes = b"",
        returncode: int = 0,
        timeout: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.timeout = timeout
        self.killed = False

    def wait(self, timeout: int | None = None) -> int:
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("docker", timeout or 0)
        return self.returncode

    def kill(self) -> None:
        self.killed = True


def request(repository: Path, **overrides: Any) -> ScannerExecutionRequest:
    values: dict[str, Any] = {
        "scanner": "bandit",
        "repository": repository,
        "image": "bandit:test",
        "command": ("bandit", "-r", "/workspace", "-f", "json"),
        "timeout_seconds": 30,
        "output_limit_bytes": 10_000,
        "success_exit_codes": (0, 1),
    }
    values.update(overrides)
    return ScannerExecutionRequest(**values)


def prepare_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(DockerScannerRunner, "_image_available", staticmethod(lambda *_: True))


def test_docker_runner_builds_locked_down_structured_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    prepare_runner(monkeypatch)
    captured: dict[str, Any] = {}

    def fake_popen(command: list[str], **kwargs: Any) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = DockerScannerRunner().execute(request(repository))

    assert result.status == ExecutionStatus.COMPLETED
    command = captured["command"]
    assert command[0] == "/usr/bin/docker"
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert f"{repository}:/workspace:ro" in command
    assert captured["kwargs"]["shell"] is False


def test_docker_runner_never_falls_back_when_image_is_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")

    result = DockerScannerRunner().execute(request(repository, image=None))

    assert result.status == ExecutionStatus.SKIPPED
    assert result.failure_reason == "scanner image is not configured"


def test_docker_runner_enforces_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    prepare_runner(monkeypatch)
    process = FakeProcess(timeout=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    result = DockerScannerRunner().execute(request(repository))

    assert result.status == ExecutionStatus.TIMEOUT
    assert process.killed is True


def test_docker_runner_rejects_oversized_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    prepare_runner(monkeypatch)
    process = FakeProcess(stdout=b"x" * 101)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    result = DockerScannerRunner().execute(request(repository, output_limit_bytes=100))

    assert result.status == ExecutionStatus.FAILED
    assert result.output_truncated is True
    assert result.stdout == ""
