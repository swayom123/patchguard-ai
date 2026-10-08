from pathlib import Path

import pytest
from pydantic import ValidationError

from patchguard.core.config import Settings


def test_colon_separated_repository_roots_are_normalized(tmp_path: Path) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"

    settings = Settings(allowed_repository_roots=f"{one}:{two}")  # type: ignore[arg-type]

    assert settings.allowed_repository_roots == [one.resolve(), two.resolve()]


def test_phase_one_rejects_write_mode(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="read-only"):
        Settings(allowed_repository_roots=[tmp_path], read_only=False)


def test_repository_roots_load_from_colon_separated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    monkeypatch.setenv("PATCHGUARD_ALLOWED_REPOSITORY_ROOTS", f"{one}:{two}")

    settings = Settings()

    assert settings.allowed_repository_roots == [one.resolve(), two.resolve()]
