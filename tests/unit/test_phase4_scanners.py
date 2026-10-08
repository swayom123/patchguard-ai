from pathlib import Path

from patchguard.domain.scanning import ExecutionStatus
from patchguard.scanners.configuration import ConfigurationScanner
from patchguard.scanners.dependencies import DependencySecurityScanner
from patchguard.scanners.secrets import SecretScanner


class _UnusedRunner:
    pass


def test_dependency_scanner_inventories_without_executing_manifest(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("safe-lib==1.2.3\nloose-lib>=2\n")

    result = DependencySecurityScanner().scan(tmp_path, _UnusedRunner())  # type: ignore[arg-type]

    assert result.status == ExecutionStatus.COMPLETED
    assert [(item.package, item.pinned) for item in result.dependencies] == [
        ("safe-lib", True),
        ("loose-lib", False),
    ]
    assert [item.rule_id for item in result.findings] == [
        "patchguard.dependencies.unpinned-direct-requirement"
    ]


def test_secret_scanner_redacts_values_and_uses_stable_hmac(tmp_path: Path) -> None:
    candidate = "not-a-real-secret-value"
    (tmp_path / "settings.py").write_text(f'api_key = "{candidate}"\n')
    scanner = SecretScanner(fingerprint_key="test-key", max_files=10, max_file_size_bytes=10_000)

    result = scanner.scan(tmp_path, _UnusedRunner())  # type: ignore[arg-type]

    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert candidate not in finding.description
    assert candidate not in finding.evidence_summary
    assert finding.evidence_details is not None
    assert finding.evidence_details["masked_value"] == "[REDACTED]"
    assert len(finding.evidence_details["secret_fingerprint"]) == 64


def test_secret_scanner_is_skipped_without_fingerprint_key(tmp_path: Path) -> None:
    result = SecretScanner(fingerprint_key=None, max_files=10, max_file_size_bytes=10_000).scan(
        tmp_path,
        _UnusedRunner(),  # type: ignore[arg-type]
    )
    assert result.status == ExecutionStatus.SKIPPED


def test_configuration_scanner_uses_literal_ast_rules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI(debug=True)\n"
        "app.add_middleware(object, allow_origins=['*'], allow_credentials=True)\n"
    )
    result = ConfigurationScanner(max_files=10, max_file_size_bytes=10_000).scan(
        tmp_path,
        _UnusedRunner(),  # type: ignore[arg-type]
    )
    assert result.status == ExecutionStatus.COMPLETED
    assert {finding.cwe_id for finding in result.findings} == {"CWE-489", "CWE-942"}
