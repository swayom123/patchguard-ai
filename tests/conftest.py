from pathlib import Path

import pytest
from fastapi import FastAPI

from patchguard.apps.api.main import create_app
from patchguard.core.config import Settings
from patchguard.domain.enums import ScanMode
from patchguard.storage.models import Base


@pytest.fixture
def authorized_root(tmp_path: Path) -> Path:
    root = tmp_path / "authorized"
    root.mkdir()
    return root


@pytest.fixture
def demo_repository(authorized_root: Path) -> Path:
    repository = authorized_root / "demo"
    (repository / "app").mkdir(parents=True)
    (repository / "tests").mkdir()
    (repository / "app" / "main.py").write_text("value = 1\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["fastapi", "pytest"]\n',
        encoding="utf-8",
    )
    return repository


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def api_app(tmp_path: Path, authorized_root: Path) -> FastAPI:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        allowed_repository_roots=[authorized_root],
        scan_mode=ScanMode.TEST,
        log_json=False,
    )
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    return application
