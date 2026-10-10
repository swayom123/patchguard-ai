from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

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


def test_production_requires_strong_api_authentication(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="production requires"):
        Settings(environment="production", allowed_repository_roots=[tmp_path])

    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(
            environment="production",
            api_auth_token=SecretStr("too-short"),
            allowed_repository_roots=[tmp_path],
        )

    settings = Settings(
        environment="production",
        api_auth_token=SecretStr("x" * 48),
        allowed_repository_roots=[tmp_path],
    )
    assert settings.api_auth_token is not None
    assert "x" * 48 not in repr(settings)
