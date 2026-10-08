import os
from dataclasses import replace
from pathlib import Path
from typing import ClassVar

from patchguard.domain.intelligence import (
    IndexedCall,
    IndexedFileResult,
    IndexedImport,
    ParseIssue,
    ParseIssueKind,
    RepositoryIndexResult,
)
from patchguard.repository.language_adapters.base import LanguageAdapter


class RepositoryIndexLimitError(ValueError):
    """Raised when safe repository indexing limits are exceeded."""


class RepositoryIndexer:
    _excluded_directories: ClassVar[set[str]] = {
        ".git",
        ".venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
    }
    _unsupported_source_languages: ClassVar[dict[str, str]] = {
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".go": "Go",
        ".rs": "Rust",
        ".cs": "C#",
        ".php": "PHP",
    }

    def __init__(self, adapters: list[LanguageAdapter], *, max_files: int = 10_000) -> None:
        self._adapters = tuple(adapters)
        self._max_files = max_files

    def index(self, repository: Path) -> RepositoryIndexResult:
        files: list[IndexedFileResult] = []
        paths, unsupported_languages = self._discover(repository)
        for path in paths:
            adapter = next((item for item in self._adapters if item.supports(path)), None)
            if adapter is not None:
                files.append(adapter.index_file(repository, path))
        resolved_files = self._resolve_imports(self._resolve_calls(files))
        issues = tuple(
            ParseIssue(
                file_path=".",
                kind=ParseIssueKind.UNSUPPORTED_LANGUAGE,
                message=f"no language adapter is available for {language}",
            )
            for language in sorted(unsupported_languages)
        )
        return RepositoryIndexResult(
            repository=repository, files=tuple(resolved_files), issues=issues
        )

    def _discover(self, repository: Path) -> tuple[list[Path], set[str]]:
        discovered: list[Path] = []
        unsupported_languages: set[str] = set()
        repository_resolved = repository.resolve()
        source_file_count = 0
        for root, directories, filenames in os.walk(repository, followlinks=False):
            root_path = Path(root)
            directories[:] = sorted(
                name
                for name in directories
                if name not in self._excluded_directories
                and self._is_contained(repository_resolved, root_path / name)
            )
            for name in sorted(filenames):
                candidate = root_path / name
                if not self._is_contained(repository_resolved, candidate):
                    continue
                if any(adapter.supports(candidate) for adapter in self._adapters):
                    source_file_count += 1
                    discovered.append(candidate)
                    if source_file_count > self._max_files:
                        raise RepositoryIndexLimitError("repository exceeds configured file limit")
                elif candidate.suffix.lower() in self._unsupported_source_languages:
                    source_file_count += 1
                    if source_file_count > self._max_files:
                        raise RepositoryIndexLimitError("repository exceeds configured file limit")
                    unsupported_languages.add(
                        self._unsupported_source_languages[candidate.suffix.lower()]
                    )
        return discovered, unsupported_languages

    @staticmethod
    def _is_contained(repository: Path, candidate: Path) -> bool:
        try:
            return candidate.resolve(strict=True).is_relative_to(repository)
        except OSError:
            return False

    @staticmethod
    def _resolve_calls(files: list[IndexedFileResult]) -> list[IndexedFileResult]:
        by_qualified: dict[str, list[str]] = {}
        by_name: dict[str, list[str]] = {}
        for file in files:
            for symbol in file.symbols:
                by_qualified.setdefault(symbol.qualified_name, []).append(symbol.key)
                by_name.setdefault(symbol.name, []).append(symbol.key)

        resolved_files = []
        for file in files:
            calls: list[IndexedCall] = []
            for call in file.calls:
                candidates = by_qualified.get(call.callee_expression, [])
                if not candidates and "." not in call.callee_expression:
                    candidates = by_name.get(call.callee_expression, [])
                if (
                    not candidates
                    and call.caller_key
                    and call.callee_expression.startswith(("self.", "cls."))
                ):
                    caller_qualified = call.caller_key.rsplit("::", 1)[-1].split("@", 1)[0]
                    class_qualified = caller_qualified.rsplit(".", 1)[0]
                    method_name = call.callee_expression.split(".", 1)[1]
                    candidates = by_qualified.get(f"{class_qualified}.{method_name}", [])
                target = candidates[0] if len(candidates) == 1 else None
                calls.append(replace(call, resolved_symbol_key=target))
            resolved_files.append(replace(file, calls=tuple(calls)))
        return resolved_files

    @staticmethod
    def _resolve_imports(files: list[IndexedFileResult]) -> list[IndexedFileResult]:
        module_paths: dict[str, list[str]] = {}
        for file in files:
            if file.module_name:
                module_paths.setdefault(file.module_name, []).append(file.path)
        resolved_files: list[IndexedFileResult] = []
        for file in files:
            imports: list[IndexedImport] = []
            for imported in file.imports:
                module = imported.module or ""
                if imported.level and file.module_name:
                    package = file.module_name.rsplit(".", 1)[0] if "." in file.module_name else ""
                    package_parts = package.split(".") if package else []
                    keep = max(0, len(package_parts) - imported.level + 1)
                    prefix = ".".join(package_parts[:keep])
                    module = ".".join(part for part in (prefix, module) if part)
                candidates = [module]
                if imported.imported_name:
                    candidates.insert(
                        0, ".".join(part for part in (module, imported.imported_name) if part)
                    )
                matches = [path for item in candidates for path in module_paths.get(item, [])]
                target = matches[0] if len(set(matches)) == 1 else None
                imports.append(replace(imported, resolved_file_path=target))
            resolved_files.append(replace(file, imports=tuple(imports)))
        return resolved_files
