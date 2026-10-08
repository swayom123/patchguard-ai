from pathlib import Path


class RepositoryBoundaryError(ValueError):
    """Raised when a path is not an authorized repository directory."""


class RepositoryBoundary:
    def __init__(self, allowed_roots: list[Path]) -> None:
        self._allowed_roots = tuple(root.expanduser().resolve() for root in allowed_roots)

    def authorize(self, requested: Path) -> Path:
        try:
            resolved = requested.expanduser().resolve(strict=True)
        except OSError as exc:
            raise RepositoryBoundaryError("repository path does not exist") from exc
        if not resolved.is_dir():
            raise RepositoryBoundaryError("repository path must be a directory")
        if not any(
            resolved == root or resolved.is_relative_to(root) for root in self._allowed_roots
        ):
            raise RepositoryBoundaryError("repository path is outside configured roots")
        return resolved
