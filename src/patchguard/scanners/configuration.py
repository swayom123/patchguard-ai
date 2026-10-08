"""AST-only framework configuration checks; importing application code is prohibited."""

from __future__ import annotations

import ast
import os
import time
from pathlib import Path

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import ExecutionStatus, NormalizedFinding, ScannerAdapterResult
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter


class ConfigurationScanner(ScannerAdapter):
    name = "patchguard-configuration"
    execution_mode = "in-process"

    def __init__(self, *, max_files: int, max_file_size_bytes: int) -> None:
        self._max_files, self._max_file_size_bytes = max_files, max_file_size_bytes

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del runner
        started = time.monotonic()
        findings: list[NormalizedFinding] = []
        count = 0
        for root, directories, names in os.walk(repository, followlinks=False):
            directories[:] = [
                item
                for item in directories
                if item not in {".git", ".venv", "node_modules", "__pycache__"}
            ]
            for name in names:
                path = Path(root) / name
                if path.suffix != ".py" or path.is_symlink():
                    continue
                count += 1
                if count > self._max_files:
                    return ScannerAdapterResult(
                        scanner=self.name,
                        status=ExecutionStatus.FAILED,
                        failure_reason="repository exceeds configured scanning limits",
                    )
                try:
                    if path.stat().st_size <= self._max_file_size_bytes:
                        findings.extend(self._scan_file(repository, path))
                except OSError:
                    continue
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(findings),
            version="1",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _scan_file(repository: Path, path: Path) -> list[NormalizedFinding]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            return []
        relative = path.relative_to(repository).as_posix()
        findings: list[NormalizedFinding] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
                and any(
                    isinstance(target, ast.Name) and target.id == "DEBUG" for target in node.targets
                )
            ):
                findings.append(
                    _finding(
                        relative,
                        node.lineno,
                        "patchguard.configuration.debug-enabled",
                        "Debug mode enabled",
                        "CWE-489",
                        "Active Debug Code",
                        Severity.MEDIUM,
                    )
                )
            if (
                isinstance(node, ast.Call)
                and _expression(node.func) in {"FastAPI", "app.run"}
                and any(
                    keyword.arg == "debug"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
            ):
                findings.append(
                    _finding(
                        relative,
                        node.lineno,
                        "patchguard.configuration.debug-enabled",
                        "Debug mode enabled",
                        "CWE-489",
                        "Active Debug Code",
                        Severity.MEDIUM,
                    )
                )
            if isinstance(node, ast.Call) and _expression(node.func).endswith("add_middleware"):
                wildcard = any(
                    keyword.arg == "allow_origins"
                    and isinstance(keyword.value, (ast.List, ast.Tuple))
                    and any(
                        isinstance(item, ast.Constant) and item.value == "*"
                        for item in keyword.value.elts
                    )
                    for keyword in node.keywords
                )
                credentials = any(
                    keyword.arg == "allow_credentials"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if wildcard and credentials:
                    findings.append(
                        _finding(
                            relative,
                            node.lineno,
                            "patchguard.configuration.permissive-cors",
                            "Permissive CORS with credentials",
                            "CWE-942",
                            "Permissive Cross-domain Policy with Untrusted Domains",
                            Severity.MEDIUM,
                        )
                    )
        return findings


def _expression(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_expression(node.value)}.{node.attr}"
    return ""


def _finding(
    path: str, line: int, rule: str, title: str, cwe: str, cwe_name: str, severity: Severity
) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="patchguard-configuration",
        rule_id=rule,
        title=title,
        description=(
            "A framework configuration pattern may expose development behavior "
            "or broaden cross-origin access."
        ),
        category="insecure-configuration",
        cwe_id=cwe,
        cwe_name=cwe_name,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=path,
        line_start=line,
        line_end=line,
        code_reference=f"{path}:{line}",
        evidence_summary="AST-only configuration rule matched a literal enabled setting.",
    )
