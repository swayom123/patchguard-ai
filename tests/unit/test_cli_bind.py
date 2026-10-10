from pathlib import Path

import pytest
from pydantic import SecretStr
from typer import BadParameter

from patchguard.apps.cli import main as cli
from patchguard.core.config import Settings


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "[::1]"])
def test_loopback_hosts_are_recognized(host: str) -> None:
    assert cli._is_loopback_host(host)


@pytest.mark.parametrize("host", ["192.0.2.10", "patchguard.example"])
def test_non_loopback_hosts_require_authentication(
    host: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: Settings(allowed_repository_roots=[tmp_path], api_auth_token=None),
    )

    with pytest.raises(BadParameter, match="requires PATCHGUARD_API_AUTH_TOKEN"):
        cli.serve(host=host, port=8000)


def test_non_loopback_host_can_start_when_api_token_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[tuple[str, int]] = []
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: Settings(
            allowed_repository_roots=[tmp_path],
            api_auth_token=SecretStr("a" * 32),
        ),
    )
    monkeypatch.setattr(
        cli.uvicorn,
        "run",
        lambda *args, **kwargs: started.append((kwargs["host"], kwargs["port"])),
    )

    cli.serve(host="192.0.2.10", port=8000)

    assert started == [("192.0.2.10", 8000)]
