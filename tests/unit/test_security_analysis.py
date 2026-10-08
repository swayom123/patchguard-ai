from pathlib import Path

from sqlalchemy.orm import Session

from patchguard.agents.security_analysis import SecurityAnalysisAgent
from patchguard.domain.analysis import ModelAssessment
from patchguard.domain.enums import AssessmentClassification, Confidence, Severity
from patchguard.models.providers.base import ModelProvider
from patchguard.storage.database import create_database_engine, create_session_factory
from patchguard.storage.models import Base, Evidence, Repository, SecurityFinding, SecurityScan


class FakeProvider(ModelProvider):
    name = "fake"
    model_name = "test-model"

    def complete(self, *, system_instruction: str, repository_context: str) -> ModelAssessment:
        assert "untrusted data" in repository_context
        assert "Assess only" in system_instruction
        return ModelAssessment(
            classification=AssessmentClassification.CONFIRMED,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence_strength=Confidence.HIGH,
            root_cause="An evidence-backed unsafe call reaches a sensitive sink.",
            reasoning_summary="The scanner evidence identifies the call and location.",
            affected_components=["service"],
            recommended_fix="Use the safe API and validate untrusted input.",
        )


def test_analysis_persists_only_validated_evidence_bound_assessment(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'analysis.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        finding = _finding(session, tmp_path)
        assessment = SecurityAnalysisAgent(
            session, FakeProvider(), context_limit_chars=10_000
        ).analyze(finding.id)

        assert assessment is not None
        assert assessment.provider == "fake"
        assert assessment.classification == AssessmentClassification.CONFIRMED.value
        assert session.get(SecurityFinding, finding.id).status == "CONFIRMED"  # type: ignore[union-attr]
        assert len(assessment.context_digest) == 64


def _finding(session: Session, tmp_path: Path) -> SecurityFinding:
    repository = Repository(path=str(tmp_path), name="repo", profile={}, read_only=True)
    session.add(repository)
    session.flush()
    scan = SecurityScan(repository_id=repository.id, mode="test")
    session.add(scan)
    session.flush()
    finding = SecurityFinding(
        repository_id=repository.id,
        scan_id=scan.id,
        fingerprint="f" * 64,
        scanner="unit",
        primary_rule_id="rule",
        title="Unsafe call",
        description="test finding",
        category="test",
        severity="MEDIUM",
        confidence="MEDIUM",
        file_path="service.py",
        line_start=1,
        line_end=1,
        status="NEW",
    )
    session.add(finding)
    session.flush()
    session.add(
        Evidence(
            finding_id=finding.id,
            scanner="unit",
            rule_id="rule",
            kind="test",
            summary="test evidence",
            details={},
        )
    )
    session.commit()
    session.refresh(finding)
    return finding
