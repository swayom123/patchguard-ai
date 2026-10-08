import ast
import hashlib
import io
import tokenize
from pathlib import Path

from patchguard.domain.intelligence import (
    ControlFlowSummary,
    IndexedCall,
    IndexedFileResult,
    IndexedImport,
    IndexedSymbol,
    ParseIssue,
    ParseIssueKind,
    SymbolKind,
)
from patchguard.repository.language_adapters.base import LanguageAdapter


class _ControlFlowVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.branches = 0
        self.loops = 0
        self.returns = 0
        self.raises = 0
        self.awaits = 0

    def visit_If(self, node: ast.If) -> None:
        self.branches += 1
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.branches += len(node.cases)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.loops += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.loops += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.loops += 1
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self.returns += 1
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.raises += 1
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        self.awaits += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def summary(self) -> ControlFlowSummary:
        return ControlFlowSummary(
            branches=self.branches,
            loops=self.loops,
            returns=self.returns,
            raises=self.raises,
            awaits=self.awaits,
        )


class _StructureVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, module_name: str) -> None:
        self.file_path = file_path
        self.module_name = module_name
        self.symbols: list[IndexedSymbol] = []
        self.imports: list[IndexedImport] = []
        self.calls: list[IndexedCall] = []
        self._scope: list[tuple[str, SymbolKind, str]] = []

    @property
    def _current_key(self) -> str | None:
        return self._scope[-1][0] if self._scope else None

    def _qualified_name(self, name: str) -> str:
        parents = [scope_name for _, _, scope_name in self._scope]
        suffix = ".".join([*parents, name]) if parents else name
        return f"{self.module_name}.{suffix}" if self.module_name else suffix

    def _add_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, asynchronous: bool
    ) -> None:
        parent_kind = self._scope[-1][1] if self._scope else None
        if parent_kind == SymbolKind.CLASS:
            kind = SymbolKind.ASYNC_METHOD if asynchronous else SymbolKind.METHOD
        else:
            kind = SymbolKind.ASYNC_FUNCTION if asynchronous else SymbolKind.FUNCTION
        qualified_name = self._qualified_name(node.name)
        key = f"{self.file_path}::{qualified_name}@{node.lineno}:{node.col_offset}"
        flow = _ControlFlowVisitor()
        for statement in node.body:
            flow.visit(statement)
        symbol = IndexedSymbol(
            key=key,
            name=node.name,
            qualified_name=qualified_name,
            kind=kind,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            column_start=node.col_offset,
            parent_key=self._current_key,
            is_public=not node.name.startswith("_"),
            control_flow=flow.summary(),
        )
        self.symbols.append(symbol)
        self._scope.append((key, kind, node.name))
        for statement in node.body:
            self.visit(statement)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node, asynchronous=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node, asynchronous=True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified_name = self._qualified_name(node.name)
        key = f"{self.file_path}::{qualified_name}@{node.lineno}:{node.col_offset}"
        symbol = IndexedSymbol(
            key=key,
            name=node.name,
            qualified_name=qualified_name,
            kind=SymbolKind.CLASS,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            column_start=node.col_offset,
            parent_key=self._current_key,
            is_public=not node.name.startswith("_"),
        )
        self.symbols.append(symbol)
        self._scope.append((key, SymbolKind.CLASS, node.name))
        for statement in node.body:
            self.visit(statement)
        self._scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                IndexedImport(
                    file_path=self.file_path,
                    module=alias.name,
                    imported_name=None,
                    alias=alias.asname,
                    level=0,
                    line=node.lineno,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.imports.append(
                IndexedImport(
                    file_path=self.file_path,
                    module=node.module,
                    imported_name=alias.name,
                    alias=alias.asname,
                    level=node.level,
                    line=node.lineno,
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        expression = self._call_expression(node.func)
        if expression is not None:
            self.calls.append(
                IndexedCall(
                    file_path=self.file_path,
                    caller_key=self._current_key,
                    callee_expression=expression[:256],
                    line=node.lineno,
                    column=node.col_offset,
                )
            )
        self.generic_visit(node)

    @classmethod
    def _call_expression(cls, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = cls._call_expression(node.value)
            return f"{parent}.{node.attr}" if parent else None
        return None


class PythonLanguageAdapter(LanguageAdapter):
    language = "Python"
    suffixes = (".py",)

    def __init__(self, *, max_file_size_bytes: int = 1_000_000) -> None:
        self._max_file_size_bytes = max_file_size_bytes

    def index_file(self, repository: Path, path: Path) -> IndexedFileResult:
        relative = path.relative_to(repository).as_posix()
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(repository.resolve()) or not resolved.is_file():
                return self._issue_result(relative, ParseIssueKind.IO_ERROR, "unsafe file path")
            size = resolved.stat().st_size
            if size > self._max_file_size_bytes:
                return self._issue_result(
                    relative,
                    ParseIssueKind.FILE_TOO_LARGE,
                    "file exceeds configured parsing limit",
                    size=size,
                )
            content = resolved.read_bytes()
        except OSError:
            return self._issue_result(relative, ParseIssueKind.IO_ERROR, "file could not be read")

        digest = hashlib.sha256(content).hexdigest()
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
            text = content.decode(encoding)
        except (LookupError, SyntaxError, UnicodeError):
            return self._issue_result(
                relative,
                ParseIssueKind.ENCODING_ERROR,
                "file encoding could not be decoded safely",
                digest=digest,
                size=len(content),
            )
        try:
            tree = ast.parse(text, filename=relative, type_comments=True)
        except SyntaxError as exc:
            return self._issue_result(
                relative,
                ParseIssueKind.SYNTAX_ERROR,
                exc.msg,
                line=exc.lineno,
                digest=digest,
                size=len(content),
            )

        module_name = self._module_name(relative)
        visitor = _StructureVisitor(relative, module_name)
        visitor.visit(tree)
        return IndexedFileResult(
            path=relative,
            language=self.language,
            sha256=digest,
            size_bytes=len(content),
            module_name=module_name,
            symbols=tuple(visitor.symbols),
            imports=tuple(visitor.imports),
            calls=tuple(visitor.calls),
        )

    @staticmethod
    def _module_name(relative: str) -> str:
        parts = list(Path(relative).with_suffix("").parts)
        if parts and parts[0] == "src":
            parts.pop(0)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _issue_result(
        self,
        relative: str,
        kind: ParseIssueKind,
        message: str,
        *,
        line: int | None = None,
        digest: str = "",
        size: int = 0,
    ) -> IndexedFileResult:
        return IndexedFileResult(
            path=relative,
            language=self.language,
            sha256=digest,
            size_bytes=size,
            module_name=self._module_name(relative),
            issues=(ParseIssue(file_path=relative, kind=kind, message=message, line=line),),
        )
