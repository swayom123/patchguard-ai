"""Narrow, bounded JavaScript/TypeScript source heuristics."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import (
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter

_DYNAMIC_CODE = re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()")
_SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_EXCLUDED = {".git", ".venv", "node_modules", "dist", "build", "coverage"}


class JavaScriptSecurityScanner(ScannerAdapter):
    """Detect explicit dynamic-code constructs without invoking a JS runtime."""

    name = "patchguard-javascript"
    execution_mode = "in-process"

    def __init__(self, *, max_files: int, max_file_size_bytes: int) -> None:
        self._max_files = max_files
        self._max_file_size_bytes = max_file_size_bytes

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del runner
        started = time.monotonic()
        findings: list[NormalizedFinding] = []
        count = 0
        root = repository.resolve()
        for current, directories, filenames in os.walk(repository, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name
                for name in directories
                if name not in _EXCLUDED and self._contained(root, current_path / name)
            ]
            for filename in sorted(filenames):
                path = current_path / filename
                if path.suffix.lower() not in _SOURCE_SUFFIXES or not self._contained(root, path):
                    continue
                count += 1
                if count > self._max_files:
                    return ScannerAdapterResult(
                        scanner=self.name,
                        status=ExecutionStatus.FAILED,
                        failure_reason="repository exceeds configured scanning limits",
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                try:
                    raw = path.read_bytes()
                except OSError:
                    continue
                if len(raw) > self._max_file_size_bytes:
                    continue
                try:
                    source = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                relative = path.relative_to(repository).as_posix()
                for match in _DYNAMIC_CODE.finditer(source):
                    line = source.count("\n", 0, match.start()) + 1
                    findings.append(
                        NormalizedFinding(
                            scanner=self.name,
                            rule_id="patchguard.javascript.dynamic-code-execution",
                            title="Dynamic code construction",
                            description=(
                                "eval() and Function() compile strings as code. Review whether "
                                "untrusted input can reach this call."
                            ),
                            category="code-injection",
                            cwe_id="CWE-95",
                            cwe_name="Improper Neutralization of Directives in Dynamically "
                            "Evaluated Code ('Eval Injection')",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=relative,
                            line_start=line,
                            line_end=line,
                            code_reference=None,
                            evidence_summary=(
                                "A dynamic JavaScript code-construction call was found."
                            ),
                            evidence_details={"construct": match.group(0).strip()},
                        )
                    )
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(findings),
            version="1",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _contained(repository: Path, path: Path) -> bool:
        try:
            return path.resolve(strict=True).is_relative_to(repository)
        except OSError:
            return False
