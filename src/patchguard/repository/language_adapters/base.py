from abc import ABC, abstractmethod
from pathlib import Path

from patchguard.domain.intelligence import IndexedFileResult


class LanguageAdapter(ABC):
    language: str
    suffixes: tuple[str, ...]

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.suffixes

    @abstractmethod
    def index_file(self, repository: Path, path: Path) -> IndexedFileResult:
        """Parse one already-authorized file without importing or executing it."""
