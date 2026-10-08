from pathlib import Path

import pytest

from patchguard.repository.boundary import RepositoryBoundary, RepositoryBoundaryError


def test_allows_directory_beneath_configured_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    repository = root / "repo"
    repository.mkdir(parents=True)

    assert RepositoryBoundary([root]).authorize(repository) == repository.resolve()


def test_rejects_path_outside_configured_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()

    with pytest.raises(RepositoryBoundaryError, match="outside configured roots"):
        RepositoryBoundary([root]).authorize(outside)


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "linked-repository"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RepositoryBoundaryError, match="outside configured roots"):
        RepositoryBoundary([root]).authorize(link)
