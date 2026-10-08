"""Conservative secret scanning which never persists candidate values."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from pathlib import Path

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import ExecutionStatus, NormalizedFinding, ScannerAdapterResult
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter

_ASSIGNMENT = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*[\"'](?P<value>[^\"'\s]{8,})"
)
_SENSITIVE_NAME = re.compile(r"(?i)(?:api[_-]?key|secret|token|password)")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}


class SecretScanner(ScannerAdapter):
    name = "patchguard-secrets"
    execution_mode = "in-process"

    def __init__(
        self, *, fingerprint_key: str | None, max_files: int, max_file_size_bytes: int
    ) -> None:
        self._key = fingerprint_key.encode() if fingerprint_key else None
        self._max_files = max_files
        self._max_file_size_bytes = max_file_size_bytes

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del runner
        started = time.monotonic()
        if self._key is None:
            return ScannerAdapterResult(
                scanner=self.name,
                status=ExecutionStatus.SKIPPED,
                failure_reason="secret fingerprint key is not configured",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        findings: list[NormalizedFinding] = []
        seen = 0
        for root, directories, names in os.walk(repository, followlinks=False):
            directories[:] = [name for name in directories if name not in _SKIP_DIRS]
            for name in names:
                path = Path(root) / name
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or path.stat().st_size > self._max_file_size_bytes
                ):
                    continue
                seen += 1
                if seen > self._max_files:
                    return ScannerAdapterResult(
                        scanner=self.name,
                        status=ExecutionStatus.FAILED,
                        failure_reason="repository exceeds configured scanning limits",
                    )
                findings.extend(self._scan_file(repository, path))
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(findings),
            version="1",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def _scan_file(self, repository: Path, path: Path) -> list[NormalizedFinding]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return []
        relative = path.relative_to(repository).as_posix()
        findings: list[NormalizedFinding] = []
        for number, line in enumerate(lines, 1):
            value: str | None = None
            rule = "patchguard.secrets.suspected-assignment"
            title = "Possible hard-coded secret"
            if _PRIVATE_KEY.search(line):
                value, rule, title = (
                    line,
                    "patchguard.secrets.private-key",
                    "Private key material in repository",
                )
            else:
                match = _ASSIGNMENT.search(line)
                if match and _SENSITIVE_NAME.search(match.group("name")):
                    value = match.group("value")
            if value is None:
                continue
            digest = hmac.new(self._key or b"", value.encode(), hashlib.sha256).hexdigest()
            findings.append(
                NormalizedFinding(
                    scanner=self.name,
                    rule_id=rule,
                    title=title,
                    description=(
                        "Potential credential material was found by a conservative static pattern. "
                        "The candidate value is redacted and was not persisted."
                    ),
                    category="hard-coded-secret",
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file_path=relative,
                    line_start=number,
                    line_end=number,
                    code_reference=f"{relative}:{number}",
                    evidence_summary="Secret pattern matched; candidate value is [REDACTED].",
                    evidence_details={"secret_fingerprint": digest, "masked_value": "[REDACTED]"},
                )
            )
        return findings
