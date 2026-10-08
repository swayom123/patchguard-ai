from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_migration_upgrades_empty_database(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    database = tmp_path / "migration.db"
    monkeypatch.setenv("PATCHGUARD_DATABASE_URL", f"sqlite:///{database}")
    config = Config("alembic.ini")

    command.upgrade(config, "head")

    assert "security_findings" in inspect(create_engine(f"sqlite:///{database}")).get_table_names()
