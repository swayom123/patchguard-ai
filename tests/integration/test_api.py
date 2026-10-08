import hashlib
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI


def repository_digest(repository: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(repository.rglob("*")):
        relative = path.relative_to(repository)
        digest.update(str(relative).encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


pytestmark = pytest.mark.anyio


async def test_health_reports_read_only(api_app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "patchguard-ai",
        "version": "0.1.0",
        "read_only": True,
    }


async def test_register_create_scan_and_list_findings_without_mutation(
    api_app: FastAPI, demo_repository: Path
) -> None:
    before = repository_digest(demo_repository)
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registration = await client.post("/repositories", json={"path": str(demo_repository)})
        assert registration.status_code == 201
        repository = registration.json()
        assert repository["read_only"] is True
        assert repository["profile"]["frameworks"] == ["FastAPI"]
        assert repository["profile"]["metadata"]["python_file_count"] == 1

        creation = await client.post(f"/repositories/{repository['id']}/scans")
        assert creation.status_code == 201
        scan = creation.json()
        assert scan["status"] == "PENDING"
        assert scan["mode"] == "test"

        status = await client.get(f"/scans/{scan['id']}")
        assert status.status_code == 200
        assert status.json()["status"] == "PENDING"

        findings = await client.get("/findings", params={"scan_id": scan["id"]})
        assert findings.status_code == 200
        assert findings.json() == {"items": [], "total": 0}
    assert repository_digest(demo_repository) == before


async def test_registration_rejects_unauthorized_path(api_app: FastAPI, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/repositories", json={"path": str(outside)})

    assert response.status_code == 403
    assert "outside configured roots" in response.json()["detail"]


async def test_scan_unknown_repository_returns_not_found(api_app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/repositories/not-a-real-id/scans")

    assert response.status_code == 404


async def test_create_and_retrieve_repository_intelligence(
    api_app: FastAPI, demo_repository: Path
) -> None:
    before = repository_digest(demo_repository)
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(demo_repository)})
        repository_id = registered.json()["id"]

        created = await client.post(f"/repositories/{repository_id}/indexes")
        assert created.status_code == 201
        summary = created.json()
        assert summary["status"] == "COMPLETED"
        assert summary["file_count"] == 1
        assert summary["symbol_count"] == 0

        symbols = await client.get(f"/indexes/{summary['id']}/symbols")
        imports = await client.get(f"/indexes/{summary['id']}/imports")
        calls = await client.get(f"/indexes/{summary['id']}/calls")
        issues = await client.get(f"/indexes/{summary['id']}/issues")
        assert symbols.json() == []
        assert imports.json() == []
        assert calls.json() == []
        assert issues.json() == []
    assert repository_digest(demo_repository) == before


async def test_unsupported_language_creates_partial_index(
    api_app: FastAPI, authorized_root: Path
) -> None:
    repository = authorized_root / "typescript-only"
    repository.mkdir()
    (repository / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(repository)})
        created = await client.post(f"/repositories/{registered.json()['id']}/indexes")
        summary = created.json()
        issues = await client.get(f"/indexes/{summary['id']}/issues")

    assert summary["status"] == "PARTIAL"
    assert summary["issue_count"] == 1
    assert issues.json()[0]["kind"] == "UNSUPPORTED_LANGUAGE"


async def test_run_defensive_scan_persists_real_findings_and_scanner_states(
    api_app: FastAPI, authorized_root: Path
) -> None:
    repository = authorized_root / "vulnerable"
    repository.mkdir()
    source = repository / "service.py"
    source.write_text(
        """import pickle
import subprocess

def unsafe(command, data):
    subprocess.run(command, shell=True)
    return pickle.loads(data)
""",
        encoding="utf-8",
    )
    before = repository_digest(repository)
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(repository)})
        repository_id = registered.json()["id"]
        indexed = await client.post(f"/repositories/{repository_id}/indexes")
        index_id = indexed.json()["id"]
        created = await client.post(f"/repositories/{repository_id}/scans")
        scan_id = created.json()["id"]
        assert created.json()["repository_index_id"] == index_id

        executed = await client.post(f"/scans/{scan_id}/run")
        assert executed.status_code == 200
        assert executed.json()["status"] == "COMPLETED"

        runs = await client.get(f"/scans/{scan_id}/scanner-runs")
        states = {item["scanner_name"]: item["status"] for item in runs.json()}
        assert states == {
            "patchguard-ast": "COMPLETED",
            "bandit": "SKIPPED",
            "semgrep": "SKIPPED",
            "patchguard-dependencies": "COMPLETED",
            "patchguard-configuration": "COMPLETED",
            "patchguard-secrets": "SKIPPED",
        }

        findings = await client.get("/findings", params={"scan_id": scan_id})
        assert findings.json()["total"] == 2
        assert {item["cwe_id"] for item in findings.json()["items"]} == {"CWE-78", "CWE-502"}
        detail = await client.get(f"/findings/{findings.json()['items'][0]['id']}")
        assert len(detail.json()["evidence"]) == 1
        assert "source" not in detail.json()["evidence"][0]["details"]

        repeated = await client.post(f"/scans/{scan_id}/run")
        assert repeated.status_code == 409

    assert repository_digest(repository) == before
