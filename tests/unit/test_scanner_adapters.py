import json
from pathlib import Path

from patchguard.domain.scanning import (
    ExecutionStatus,
    ScannerExecutionRequest,
    ScannerExecutionResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.bandit import BanditScanner
from patchguard.scanners.custom_python import CustomPythonScanner
from patchguard.scanners.semgrep import SemgrepScanner


class FakeRunner(ScannerRunner):
    def __init__(self, result: ScannerExecutionResult) -> None:
        self.result = result
        self.request: ScannerExecutionRequest | None = None

    def execute(self, request: ScannerExecutionRequest) -> ScannerExecutionResult:
        self.request = request
        return self.result


def test_custom_scanner_detects_narrow_defensive_rules(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "unsafe.py").write_text(
        """import pickle
import subprocess

def run(command, cursor, value, data):
    subprocess.run(command, shell=True)
    cursor.execute(f"SELECT {value}")
    return pickle.loads(data)
""",
        encoding="utf-8",
    )

    scanner = CustomPythonScanner(max_files=100, max_file_size_bytes=100_000)
    result = scanner.scan(repository, FakeRunner(ScannerExecutionResult(ExecutionStatus.SKIPPED)))

    assert result.status == ExecutionStatus.COMPLETED
    assert {finding.cwe_id for finding in result.findings} == {"CWE-78", "CWE-89", "CWE-502"}


def test_custom_scanner_does_not_flag_parameterized_sql_or_shell_false(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "safe.py").write_text(
        """import subprocess

def run(cursor, value):
    subprocess.run(["echo", value], shell=False)
    cursor.execute("SELECT * FROM users WHERE id = ?", (value,))
""",
        encoding="utf-8",
    )

    result = CustomPythonScanner(max_files=100, max_file_size_bytes=100_000).scan(
        repository, FakeRunner(ScannerExecutionResult(ExecutionStatus.SKIPPED))
    )

    assert result.findings == ()


def test_bandit_normalization_masks_messages_and_rejects_escaping_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "service.py").write_text("value = 1\n", encoding="utf-8")
    sensitive_marker = "demo-sensitive-value-that-must-not-persist"
    payload = {
        "results": [
            {
                "filename": "/workspace/service.py",
                "line_number": 1,
                "line_range": [1],
                "test_id": "B602",
                "issue_text": sensitive_marker,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
            },
            {"filename": "../outside.py", "line_number": 1, "test_id": "B602"},
        ]
    }
    runner = FakeRunner(
        ScannerExecutionResult(status=ExecutionStatus.COMPLETED, stdout=json.dumps(payload))
    )

    result = BanditScanner(image="bandit:test", timeout_seconds=30, output_limit_bytes=10_000).scan(
        repository, runner
    )

    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].cwe_id == "CWE-78"
    assert sensitive_marker not in repr(result.findings)


def test_semgrep_normalizes_known_rule_and_internal_path(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "service.py").write_text("value = 1\n", encoding="utf-8")
    payload = {
        "results": [
            {
                "check_id": "patchguard.python.unsafe-pickle",
                "path": "/workspace/service.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "ERROR"},
            }
        ]
    }
    runner = FakeRunner(
        ScannerExecutionResult(status=ExecutionStatus.COMPLETED, stdout=json.dumps(payload))
    )

    result = SemgrepScanner(
        image="semgrep:test", timeout_seconds=30, output_limit_bytes=10_000
    ).scan(repository, runner)

    assert result.status == ExecutionStatus.COMPLETED
    assert result.findings[0].cwe_id == "CWE-502"
    assert runner.request is not None
    assert runner.request.rules_directory is not None


def test_external_scanner_reports_malformed_json_as_failure(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    runner = FakeRunner(ScannerExecutionResult(status=ExecutionStatus.COMPLETED, stdout="not-json"))

    result = BanditScanner(image="bandit:test", timeout_seconds=30, output_limit_bytes=10_000).scan(
        repository, runner
    )

    assert result.status == ExecutionStatus.FAILED
    assert result.failure_reason == "scanner returned malformed JSON"
