import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from patchguard.storage.models import Evidence, SecurityFinding, SecurityPatch


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
    (repository / "index.java").write_text("class Example {}\n", encoding="utf-8")
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(repository)})
        created = await client.post(f"/repositories/{registered.json()['id']}/indexes")
        summary = created.json()
        issues = await client.get(f"/indexes/{summary['id']}/issues")

    assert summary["status"] == "PARTIAL"
    assert summary["issue_count"] == 1
    assert issues.json()[0]["kind"] == "UNSUPPORTED_LANGUAGE"


async def test_patch_plan_and_verification_api_persist_honest_states(
    api_app: FastAPI, demo_repository: Path
) -> None:
    source_path = demo_repository / "app" / "main.py"
    source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(demo_repository)})
        repository_id = registered.json()["id"]
        created_scan = await client.post(f"/repositories/{repository_id}/scans")
        scan_id = created_scan.json()["id"]
        with api_app.state.session_factory() as session:
            finding = SecurityFinding(
                repository_id=repository_id,
                scan_id=scan_id,
                fingerprint="a" * 64,
                scanner="test",
                primary_rule_id="test-rule",
                title="Test vulnerability",
                description="test evidence-backed finding",
                category="test",
                severity="MEDIUM",
                confidence="HIGH",
                file_path="app/main.py",
                line_start=1,
                line_end=1,
                status="NEW",
            )
            session.add(finding)
            session.flush()
            session.add(
                Evidence(
                    finding_id=finding.id,
                    scanner="test",
                    rule_id="test-rule",
                    kind="test",
                    summary="generic evidence",
                    details={},
                )
            )
            patch = SecurityPatch(
                finding_id=finding.id,
                file_path="app/main.py",
                operation="UPDATE",
                original_hash=source_hash,
                diff="--- a/app/main.py\n+++ b/app/main.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n",
                reason="test proposal",
                status="PROPOSED",
            )
            session.add(patch)
            session.commit()
            finding_id = finding.id
            patch_id = patch.id

        plan_response = await client.post(f"/findings/{finding_id}/patch-plans")
        verification_response = await client.post(f"/patches/{patch_id}/verify")
        invalid_triage_response = await client.patch(
            f"/findings/{finding_id}/triage",
            json={"status": "VERIFIED", "note": "Cannot skip the triage lifecycle."},
        )
        triage_response = await client.patch(
            f"/findings/{finding_id}/triage",
            json={"status": "CONFIRMED", "note": "Reviewed scanner evidence."},
        )
        expired_suppression_response = await client.post(
            f"/findings/{finding_id}/suppressions",
            json={
                "reason": "This suppression is already expired.",
                "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
            },
        )
        suppression_response = await client.post(
            f"/findings/{finding_id}/suppressions",
            json={
                "reason": "Accepted temporary risk during a release freeze.",
                "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
            },
        )
        duplicate_suppression_response = await client.post(
            f"/findings/{finding_id}/suppressions",
            json={"reason": "Duplicate active suppression."},
        )
        hidden_by_default = await client.get("/findings", params={"scan_id": scan_id})
        included = await client.get(
            "/findings", params={"scan_id": scan_id, "include_suppressed": "true"}
        )
        unsuppression_response = await client.post(f"/findings/{finding_id}/unsuppressions")
        visible_after_unsuppress = await client.get("/findings", params={"scan_id": scan_id})
        detail_response = await client.get(f"/findings/{finding_id}")

    assert plan_response.status_code == 201
    assert plan_response.json()["files_to_modify"] == ["app/main.py"]
    assert verification_response.status_code == 201
    assert verification_response.json()["status"] == "REVIEW_REQUIRED"
    assert triage_response.status_code == 200
    assert triage_response.json()["previous_status"] == "NEW"
    assert invalid_triage_response.status_code == 409
    assert expired_suppression_response.status_code == 422
    assert suppression_response.status_code == 201
    assert duplicate_suppression_response.status_code == 409
    assert hidden_by_default.json()["total"] == 0
    assert included.json()["total"] == 1
    assert unsuppression_response.status_code == 200
    assert unsuppression_response.json()["revoked_at"] is not None
    assert visible_after_unsuppress.json()["total"] == 1
    detail = detail_response.json()
    assert len(detail["patch_plans"]) == 1
    assert detail["patches"][0]["id"] == patch_id
    assert len(detail["triage_events"]) == 1
    assert len(detail["suppressions"]) == 1


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
            "patchguard-javascript": "COMPLETED",
            "bandit": "SKIPPED",
            "semgrep": "SKIPPED",
            "patchguard-dependencies": "COMPLETED",
            "patchguard-advisories": "SKIPPED",
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


async def test_offline_advisory_finding_is_persisted_with_snapshot_provenance(
    api_app: FastAPI, authorized_root: Path, tmp_path: Path
) -> None:
    repository = authorized_root / "advisory-repo"
    repository.mkdir()
    (repository / "requirements.txt").write_text("urllib3==1.26.1\n", encoding="utf-8")
    snapshot = tmp_path / "advisories.json"
    snapshot.write_text(
        json.dumps(
            {
                "format_version": 1,
                "source": "integration-fixture",
                "generated_at": datetime.now(UTC).isoformat(),
                "advisories": [
                    {
                        "id": "CVE-2025-12345",
                        "package": "urllib3",
                        "affected": "<1.26.5",
                        "fixed_version": "1.26.5",
                        "severity": "HIGH",
                        "summary": "Fixture advisory for vulnerable urllib3 versions.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    api_app.state.settings.advisory_database_path = snapshot
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        registered = await client.post("/repositories", json={"path": str(repository)})
        repository_id = registered.json()["id"]
        scan = await client.post(f"/repositories/{repository_id}/scans")
        await client.post(f"/scans/{scan.json()['id']}/run")
        results = await client.get(
            "/findings",
            params={"scan_id": scan.json()["id"], "category": "dependency-vulnerability"},
        )
        detail = await client.get(f"/findings/{results.json()['items'][0]['id']}")

    assert results.status_code == 200
    assert results.json()["total"] == 1
    assert results.json()["items"][0]["severity"] == "HIGH"
    details = detail.json()["evidence"][0]["details"]
    assert details["advisory_source"] == "integration-fixture"
    assert details["installed_version"] == "1.26.1"
    assert len(details["advisory_snapshot_sha256"]) == 64
