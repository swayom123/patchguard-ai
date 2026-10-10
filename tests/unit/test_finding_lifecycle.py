from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from patchguard.apps.cli import main as cli
from patchguard.domain.enums import FindingStatus
from patchguard.findings.lifecycle import FindingLifecycleError, FindingLifecycleService
from patchguard.storage.database import create_database_engine, create_session_factory
from patchguard.storage.models import (
    Base,
    Evidence,
    FindingSuppression,
    FindingTriageEvent,
    Repository,
    SecurityFinding,
    SecurityScan,
)


@pytest.fixture
def lifecycle_database(tmp_path: Path) -> tuple[sessionmaker, SecurityFinding]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        repository = Repository(path=str(tmp_path), name="repo", profile={})
        session.add(repository)
        session.flush()
        scan = SecurityScan(repository_id=repository.id, mode="test")
        session.add(scan)
        session.flush()
        finding = SecurityFinding(
            repository_id=repository.id,
            scan_id=scan.id,
            fingerprint="a" * 64,
            scanner="test",
            primary_rule_id="test-rule",
            title="Test finding",
            description="finding for lifecycle tests",
            category="test",
            severity="MEDIUM",
            confidence="HIGH",
            file_path="app.py",
            line_start=1,
            line_end=1,
            status=FindingStatus.NEW.value,
        )
        session.add(finding)
        session.flush()
        session.add(
            Evidence(
                finding_id=finding.id,
                scanner="test",
                rule_id="test-rule",
                kind="test",
                summary="fixture evidence",
                details={},
            )
        )
        session.commit()
        session.expunge(finding)
        yield factory, finding
    engine.dispose()


def test_lifecycle_service_records_state_changes_and_rejects_illegal_transition(
    lifecycle_database: tuple[sessionmaker, SecurityFinding],
) -> None:
    factory, detached_finding = lifecycle_database
    with factory() as session:
        service = FindingLifecycleService(session)
        event = service.triage(detached_finding.id, FindingStatus.CONFIRMED, "Reviewed evidence")
        assert event is not None
        with pytest.raises(FindingLifecycleError, match="cannot transition"):
            service.triage(detached_finding.id, FindingStatus.CONFIRMED, "No status change")


def test_cli_commands_persist_triage_and_suppression_history(
    lifecycle_database: tuple[sessionmaker, SecurityFinding], monkeypatch: pytest.MonkeyPatch
) -> None:
    factory, detached_finding = lifecycle_database
    monkeypatch.setattr(cli, "_session_factory", lambda: factory)

    cli.triage_finding(detached_finding.id, "CONFIRMED", "Reviewed evidence")
    cli.suppress_finding(detached_finding.id, "Accepted for current release")
    cli.unsuppress_finding(detached_finding.id)

    with factory() as session:
        finding = session.get(SecurityFinding, detached_finding.id)
        event = session.query(FindingTriageEvent).one()
        suppression = session.query(FindingSuppression).one()
        assert finding is not None and finding.status == FindingStatus.CONFIRMED.value
        assert event.previous_status == FindingStatus.NEW.value
        assert event.new_status == FindingStatus.CONFIRMED.value
        assert suppression.revoked_at is not None
