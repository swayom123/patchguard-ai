from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class IndexStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class SymbolKind(StrEnum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    ASYNC_FUNCTION = "ASYNC_FUNCTION"
    METHOD = "METHOD"
    ASYNC_METHOD = "ASYNC_METHOD"


class ParseIssueKind(StrEnum):
    SYNTAX_ERROR = "SYNTAX_ERROR"
    ENCODING_ERROR = "ENCODING_ERROR"
    IO_ERROR = "IO_ERROR"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"


@dataclass(frozen=True, slots=True)
class ControlFlowSummary:
    branches: int = 0
    loops: int = 0
    returns: int = 0
    raises: int = 0
    awaits: int = 0


@dataclass(frozen=True, slots=True)
class IndexedSymbol:
    key: str
    name: str
    qualified_name: str
    kind: SymbolKind
    file_path: str
    line_start: int
    line_end: int
    column_start: int
    parent_key: str | None = None
    is_public: bool = True
    control_flow: ControlFlowSummary = field(default_factory=ControlFlowSummary)


@dataclass(frozen=True, slots=True)
class IndexedImport:
    file_path: str
    module: str | None
    imported_name: str | None
    alias: str | None
    level: int
    line: int
    resolved_file_path: str | None = None


@dataclass(frozen=True, slots=True)
class IndexedCall:
    file_path: str
    caller_key: str | None
    callee_expression: str
    line: int
    column: int
    resolved_symbol_key: str | None = None


@dataclass(frozen=True, slots=True)
class ParseIssue:
    file_path: str
    kind: ParseIssueKind
    message: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class IndexedFileResult:
    path: str
    language: str
    sha256: str
    size_bytes: int
    module_name: str | None = None
    symbols: tuple[IndexedSymbol, ...] = ()
    imports: tuple[IndexedImport, ...] = ()
    calls: tuple[IndexedCall, ...] = ()
    issues: tuple[ParseIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class RepositoryIndexResult:
    repository: Path
    files: tuple[IndexedFileResult, ...]
    issues: tuple[ParseIssue, ...] = ()


class TaintEndpointKind(StrEnum):
    SOURCE = "SOURCE"
    SINK = "SINK"
    SANITIZER = "SANITIZER"


@dataclass(frozen=True, slots=True)
class TaintEndpoint:
    name: str
    kind: TaintEndpointKind
    categories: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DataFlow:
    source: str
    transformations: tuple[str, ...]
    sink: str
    sanitizers: tuple[str, ...] = ()
