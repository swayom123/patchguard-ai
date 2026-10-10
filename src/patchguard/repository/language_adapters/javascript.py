"""Bounded, non-executing structural hints for JavaScript and TypeScript."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from patchguard.domain.intelligence import (
    IndexedCall,
    IndexedFileResult,
    IndexedImport,
    IndexedSymbol,
    ParseIssue,
    ParseIssueKind,
    SymbolKind,
)
from patchguard.repository.language_adapters.base import LanguageAdapter

_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:export\s+)?(?:(?:default|declare|abstract)\s+)*(?:(async)\s+)?"
    r"(function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)"
)
_ARROW = re.compile(
    r"(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(async\s*)?(?:\([^\n]*?\)|[A-Za-z_$][\w$]*)\s*=>"
)
_IMPORT = re.compile(r"(?m)^[ \t]*import\s+(?:[^\n;]*?\s+from\s+)?['\"]([^'\"]+)['\"]")
_CALL = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")


class JavaScriptLanguageAdapter(LanguageAdapter):
    """Best-effort source metadata; regex matches never execute or resolve code."""

    language = "JavaScript/TypeScript"
    suffixes = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

    def __init__(self, *, max_file_size_bytes: int = 1_000_000) -> None:
        self._max_file_size_bytes = max_file_size_bytes

    def index_file(self, repository: Path, path: Path) -> IndexedFileResult:
        relative = path.relative_to(repository).as_posix()
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(repository.resolve()) or not resolved.is_file():
                return self._issue(relative, ParseIssueKind.IO_ERROR, "unsafe file path")
            raw = resolved.read_bytes()
        except OSError:
            return self._issue(relative, ParseIssueKind.IO_ERROR, "file could not be read")
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) > self._max_file_size_bytes:
            return self._issue(
                relative,
                ParseIssueKind.FILE_TOO_LARGE,
                "file exceeds configured parsing limit",
                digest,
                len(raw),
            )
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self._issue(
                relative, ParseIssueKind.ENCODING_ERROR, "file is not valid UTF-8", digest, len(raw)
            )

        module = relative.rsplit(".", 1)[0].replace("/", ".")
        symbols: list[IndexedSymbol] = []
        ranges: list[tuple[int, int, str]] = []
        for match in (*_DECLARATION.finditer(source), *_ARROW.finditer(source)):
            if match.re is _DECLARATION:
                name = match.group(3)
                kind_name = match.group(2)
                asynchronous = bool(match.group(1))
                kind = (
                    SymbolKind.CLASS
                    if kind_name in {"class", "interface", "enum"}
                    else SymbolKind.ASYNC_FUNCTION
                    if asynchronous
                    else SymbolKind.FUNCTION
                )
            else:
                name = match.group(1)
                kind = SymbolKind.ASYNC_FUNCTION if match.group(2) else SymbolKind.FUNCTION
            line = source.count("\n", 0, match.start()) + 1
            col = match.start() - (source.rfind("\n", 0, match.start()) + 1)
            qualified = f"{module}.{name}"
            key = f"{relative}::{qualified}@{line}:{col}"
            symbols.append(
                IndexedSymbol(
                    key=key,
                    name=name,
                    qualified_name=qualified,
                    kind=kind,
                    file_path=relative,
                    line_start=line,
                    line_end=line,
                    column_start=col,
                    is_public=not name.startswith("_"),
                )
            )
            ranges.append((match.start(), len(source), key))
        imports = tuple(
            IndexedImport(
                file_path=relative,
                module=match.group(1),
                imported_name=None,
                alias=None,
                level=0,
                line=source.count("\n", 0, match.start()) + 1,
            )
            for match in _IMPORT.finditer(source)
        )
        calls = []
        for match in _CALL.finditer(source):
            if re.search(r"\bfunction\s+$", source[max(0, match.start() - 32) : match.start()]):
                continue
            line = source.count("\n", 0, match.start()) + 1
            scope = next(
                (key for start, end, key in reversed(ranges) if start <= match.start() < end), None
            )
            calls.append(
                IndexedCall(
                    file_path=relative,
                    caller_key=scope,
                    callee_expression=match.group(1)[:256],
                    line=line,
                    column=match.start() - (source.rfind("\n", 0, match.start()) + 1),
                )
            )
        return IndexedFileResult(
            path=relative,
            language=self.language,
            sha256=digest,
            size_bytes=len(raw),
            module_name=module,
            symbols=tuple(symbols),
            imports=imports,
            calls=tuple(calls),
        )

    @staticmethod
    def _issue(
        path: str, kind: ParseIssueKind, message: str, digest: str = "", size: int = 0
    ) -> IndexedFileResult:
        return IndexedFileResult(
            path=path,
            language="JavaScript/TypeScript",
            sha256=digest,
            size_bytes=size,
            issues=(ParseIssue(path, kind, message),),
        )
