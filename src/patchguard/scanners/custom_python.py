import ast
import io
import os
import time
import tokenize
from pathlib import Path

from patchguard.domain.scanning import ExecutionStatus, NormalizedFinding, ScannerAdapterResult
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter
from patchguard.scanners.rules import DYNAMIC_SQL, SUBPROCESS_SHELL, UNSAFE_PICKLE, RuleDescriptor


class _SecurityRuleVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[NormalizedFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._expression(node.func)
        if callee in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        } and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            self._add(node, "patchguard.python.subprocess-shell-true", SUBPROCESS_SHELL)
        if (
            callee is not None
            and callee.endswith(".execute")
            and node.args
            and self._is_dynamic_string(node.args[0])
        ):
            self._add(node, "patchguard.python.dynamic-sql-execute", DYNAMIC_SQL)
        if callee in {"pickle.load", "pickle.loads"}:
            self._add(node, "patchguard.python.unsafe-pickle", UNSAFE_PICKLE)
        self.generic_visit(node)

    def _add(self, node: ast.Call, rule_id: str, descriptor: RuleDescriptor) -> None:
        self.findings.append(
            NormalizedFinding(
                scanner="patchguard-ast",
                rule_id=rule_id,
                title=descriptor.title,
                description=descriptor.description,
                category=descriptor.category,
                cwe_id=descriptor.cwe_id,
                cwe_name=descriptor.cwe_name,
                severity=descriptor.severity,
                confidence=descriptor.confidence,
                file_path=self.file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                code_reference=f"{self.file_path}:{node.lineno}",
                evidence_summary=f"PatchGuard AST rule {rule_id} matched this call structure.",
            )
        )

    @classmethod
    def _expression(cls, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = cls._expression(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None

    @staticmethod
    def _is_dynamic_string(node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        )


class CustomPythonScanner(ScannerAdapter):
    name = "patchguard-ast"
    execution_mode = "in-process"

    def __init__(self, *, max_files: int, max_file_size_bytes: int) -> None:
        self._max_files = max_files
        self._max_file_size_bytes = max_file_size_bytes

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del runner
        started = time.monotonic()
        findings: list[NormalizedFinding] = []
        count = 0
        for root, directories, filenames in os.walk(repository, followlinks=False):
            root_path = Path(root)
            directories[:] = [
                name
                for name in directories
                if name not in {".git", ".venv", "node_modules", "__pycache__"}
                and self._contained(repository, root_path / name)
            ]
            for name in filenames:
                path = root_path / name
                if path.suffix != ".py" or not self._contained(repository, path):
                    continue
                count += 1
                if count > self._max_files:
                    return self._failure(started, "repository exceeds configured scanning limits")
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
            content = path.read_bytes()
            if len(content) > self._max_file_size_bytes:
                return []
            encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
            tree = ast.parse(content.decode(encoding), filename=path.name)
        except (OSError, SyntaxError, UnicodeError, LookupError):
            return []
        visitor = _SecurityRuleVisitor(path.relative_to(repository).as_posix())
        visitor.visit(tree)
        return visitor.findings

    @staticmethod
    def _contained(repository: Path, path: Path) -> bool:
        try:
            return path.resolve(strict=True).is_relative_to(repository.resolve())
        except OSError:
            return False

    @staticmethod
    def _failure(started: float, reason: str) -> ScannerAdapterResult:
        return ScannerAdapterResult(
            scanner="patchguard-ast",
            status=ExecutionStatus.FAILED,
            duration_ms=int((time.monotonic() - started) * 1000),
            failure_reason=reason,
        )
