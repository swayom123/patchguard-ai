from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from patchguard.apps.api.main import create_app
from patchguard.core.config import Settings
from patchguard.storage.models import Base

pytestmark = pytest.mark.anyio


@pytest.fixture
def production_api(tmp_path: Path, authorized_root: Path) -> FastAPI:
    app = create_app(
        Settings(
            environment="production",
            api_auth_token=SecretStr("deployment-test-token-" + "x" * 40),
            database_url=f"sqlite:///{tmp_path / 'production.db'}",
            allowed_repository_roots=[authorized_root],
            log_json=False,
        )
    )
    Base.metadata.create_all(app.state.engine)
    return app


async def test_production_api_authenticates_all_but_health_and_hides_docs(
    production_api: FastAPI,
) -> None:
    transport = httpx.ASGITransport(app=production_api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/health")
        unauthenticated = await client.get("/repositories")
        invalid = await client.get(
            "/repositories", headers={"Authorization": "Bearer invalid-token"}
        )
        authenticated = await client.get(
            "/repositories",
            headers={"Authorization": "Bearer deployment-test-token-" + "x" * 40},
        )
        docs = await client.get(
            "/docs", headers={"Authorization": "Bearer deployment-test-token-" + "x" * 40}
        )
        schema = await client.get(
            "/openapi.json",
            headers={"Authorization": "Bearer deployment-test-token-" + "x" * 40},
        )

    assert health.status_code == 200
    assert "deployment-test-token" not in health.text
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert authenticated.status_code == 200 and authenticated.json() == []
    assert docs.status_code == 404
    assert schema.status_code == 404
