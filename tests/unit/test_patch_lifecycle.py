from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.agents.patch_generation import PatchGenerationAgent, PatchGenerationError
from patchguard.agents.patch_planning import PatchPlanningAgent
from patchguard.domain.analysis import ModelAssessment, ModelPatchProposal
from patchguard.domain.enums import AssessmentClassification, Confidence, PatchStatus, Severity
from patchguard.models.providers.base import ModelProvider
from patchguard.patching.applications import PatchApplicationError, PatchApplicationService
from patchguard.patching.workspaces import PatchWorkspaceError, PatchWorkspaceService
from patchguard.repository.boundary import RepositoryBoundary
from patchguard.storage.database import create_database_engine, create_session_factory
from patchguard.storage.models import (
    Base,
    Evidence,
    PatchApplication,
    PatchWorkspace,
    Repository,
    SecurityFinding,
    SecurityPatch,
    SecurityPatchPlan,
    SecurityScan,
)
from patchguard.verification.service import PatchVerificationService

DIFF = "--- a/app/main.py\n+++ b/app/main.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"


class FakePatchProvider(ModelProvider):
    name = "fake"
    model_name = "test-model"

    def complete(self, *, system_instruction: str, repository_context: str) -> ModelAssessment:
        del system_instruction, repository_context
        return ModelAssessment(
            classification=AssessmentClassification.CONFIRMED,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence_strength=Confidence.HIGH,
            root_cause="unsafe input reaches a sensitive sink",
            reasoning_summary="evidence identifies the unsafe call",
            recommended_fix="validate input",
        )

    def generate_patch(
        self, *, system_instruction: str, repository_context: str
    ) -> ModelPatchProposal:
        assert "untrusted data" in system_instruction
        assert "value = 1" in repository_context
        return ModelPatchProposal(diff=DIFF, reason="Use the corrected value.")


@pytest.fixture
def patch_context(tmp_path: Path) -> tuple[Session, Path, Path, Path, SecurityFinding]:
    allowed_root = tmp_path / "allowed"
    repository_path = allowed_root / "repo"
    (repository_path / "app").mkdir(parents=True)
    target = repository_path / "app" / "main.py"
    target.write_text("value = 1\n", encoding="utf-8")
    engine = create_database_engine(f"sqlite:///{tmp_path / 'patch.db'}")
    Base.metadata.create_all(engine)
    session = create_session_factory(engine)()
    repository = Repository(path=str(repository_path), name="repo", profile={"test_frameworks": []})
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
        title="Unsafe value",
        description="test finding",
        category="test",
        severity="HIGH",
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
            scanner="unit",
            rule_id="rule",
            kind="test",
            summary="reproducible evidence",
            details={},
        )
    )
    session.commit()
    yield session, allowed_root, repository_path, tmp_path, finding
    session.close()
    engine.dispose()


def _patch(
    session: Session, finding: SecurityFinding, *, status: str = "PROPOSED"
) -> SecurityPatch:
    source = (
        Path(session.get(Repository, finding.repository_id).path) / finding.file_path
    ).read_bytes()  # type: ignore[union-attr]
    patch = SecurityPatch(
        finding_id=finding.id,
        file_path=finding.file_path,
        operation="UPDATE",
        original_hash=sha256(source).hexdigest(),
        diff=DIFF,
        reason="test change",
        status=status,
    )
    session.add(patch)
    session.commit()
    session.refresh(patch)
    return patch


def test_planning_and_generation_persist_constrained_records(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, _, finding = patch_context

    plan = PatchPlanningAgent(session).plan(finding.id)
    patch = PatchGenerationAgent(
        session,
        FakePatchProvider(),
        RepositoryBoundary([allowed_root]),
        context_limit_chars=10_000,
        max_source_file_bytes=10_000,
    ).generate(finding.id)

    assert plan is not None and plan.files_to_modify == ["app/main.py"]
    assert len(plan.context_digest) == 64
    assert patch is not None and patch.status == PatchStatus.PROPOSED.value
    assert patch.original_hash == sha256(b"value = 1\n").hexdigest()
    assert (repository_path / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"
    assert len(list(session.scalars(select(SecurityPatchPlan)))) == 1


def test_generation_refuses_path_traversal_without_calling_provider(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, _, _, finding = patch_context
    finding.file_path = "../outside.py"
    session.commit()

    with pytest.raises(PatchGenerationError, match="safe repository-relative"):
        PatchGenerationAgent(
            session,
            FakePatchProvider(),
            RepositoryBoundary([allowed_root]),
            context_limit_chars=10_000,
            max_source_file_bytes=10_000,
        ).generate(finding.id)


def test_verification_review_required_without_image_never_changes_source(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, _, finding = patch_context
    patch = _patch(session, finding)
    service = PatchVerificationService(
        session,
        RepositoryBoundary([allowed_root]),
        runner=None,  # type: ignore[arg-type]
        image=None,
        timeout_seconds=1,
        output_limit_bytes=10_000,
        max_files=100,
        max_workspace_bytes=100_000,
        max_source_file_bytes=10_000,
    )

    from patchguard.core.interfaces import VerificationRequest

    run = service.verify(
        VerificationRequest(patch_id=patch.id, repository_id=finding.repository_id)
    )

    assert run is not None and run.status == "REVIEW_REQUIRED"
    assert patch.status == PatchStatus.PROPOSED.value
    assert (repository_path / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"


def test_workspace_is_materialized_once_and_source_remains_unchanged(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    service = PatchWorkspaceService(
        session,
        RepositoryBoundary([allowed_root]),
        workspace_root=tmp_path / "review-workspaces",
        max_files=100,
        max_workspace_bytes=100_000,
        max_source_file_bytes=10_000,
    )

    workspace = service.create(patch.id)
    repeated = service.create(patch.id)

    assert workspace is not None and repeated is not None
    assert workspace.id == repeated.id
    assert (Path(workspace.workspace_path) / "app/main.py").read_text(encoding="utf-8") == (
        "value = 2\n"
    )
    assert (Path(workspace.workspace_path) / ".git").exists() is False
    assert (repository_path / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"


def _link_worktree(root: Path) -> Path:
    worktree = root / "linked"
    (worktree / "app").mkdir(parents=True)
    (worktree / "app/main.py").write_text("value = 1\n", encoding="utf-8")
    git_dir = root / "git-metadata" / "worktrees" / "linked"
    git_dir.mkdir(parents=True)
    (git_dir / "commondir").write_text("../..\n", encoding="utf-8")
    (worktree / ".git").write_text("gitdir: ../git-metadata/worktrees/linked\n", encoding="utf-8")
    return worktree


def _application_service(
    session: Session, allowed_root: Path, backup_root: Path
) -> PatchApplicationService:
    return PatchApplicationService(
        session,
        RepositoryBoundary([allowed_root]),
        backup_root=backup_root,
        max_source_file_bytes=10_000,
    )


def test_apply_and_rollback_preserve_backup_and_registered_checkout(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    workspace_path = tmp_path / "review-workspaces" / patch.id
    workspace_path.mkdir(parents=True)
    session.add(
        PatchWorkspace(
            patch_id=patch.id,
            repository_id=finding.repository_id,
            workspace_path=str(workspace_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
        )
    )
    session.commit()
    worktree = _link_worktree(allowed_root)
    service = _application_service(session, allowed_root, tmp_path / "private-patch-state")

    application = service.apply(patch.id, worktree, patch.id)
    assert application is not None and application.status == "APPLIED"
    assert (worktree / "app/main.py").read_text(encoding="utf-8") == "value = 2\n"
    assert Path(application.backup_path).read_text(encoding="utf-8") == "value = 1\n"
    assert (repository_path / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"

    rolled_back = service.rollback(application.id)
    assert rolled_back is not None and rolled_back.status == "ROLLED_BACK"
    assert (worktree / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"
    assert patch.status == PatchStatus.VERIFIED.value


def test_rollback_refuses_to_overwrite_post_application_edit(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, _, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    workspace_path = tmp_path / "review-workspaces" / patch.id
    workspace_path.mkdir(parents=True)
    session.add(
        PatchWorkspace(
            patch_id=patch.id,
            repository_id=finding.repository_id,
            workspace_path=str(workspace_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
        )
    )
    session.commit()
    worktree = _link_worktree(allowed_root)
    service = _application_service(session, allowed_root, tmp_path / "private-patch-state")
    application = service.apply(patch.id, worktree, patch.id)
    assert application is not None
    target = worktree / "app/main.py"
    target.write_text("operator edit\n", encoding="utf-8")

    with pytest.raises(PatchApplicationError, match="changed since application"):
        service.rollback(application.id)

    assert target.read_text(encoding="utf-8") == "operator edit\n"
    assert application.status == "APPLIED"


def test_apply_rejects_main_checkout_and_unconfirmed_patch(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    workspace_path = tmp_path / "review-workspaces" / patch.id
    workspace_path.mkdir(parents=True)
    session.add(
        PatchWorkspace(
            patch_id=patch.id,
            repository_id=finding.repository_id,
            workspace_path=str(workspace_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
        )
    )
    session.commit()
    service = _application_service(session, allowed_root, tmp_path / "private-patch-state")

    with pytest.raises(PatchApplicationError, match="confirmation"):
        service.apply(patch.id, _link_worktree(allowed_root), "wrong")
    with pytest.raises(PatchApplicationError, match="registered repository"):
        service.apply(patch.id, repository_path, patch.id)

    assert (repository_path / "app/main.py").read_text(encoding="utf-8") == "value = 1\n"


def test_apply_rejects_stale_worktree_without_creating_application(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, _, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    workspace_path = tmp_path / "review-workspaces" / patch.id
    workspace_path.mkdir(parents=True)
    session.add(
        PatchWorkspace(
            patch_id=patch.id,
            repository_id=finding.repository_id,
            workspace_path=str(workspace_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
        )
    )
    session.commit()
    worktree = _link_worktree(allowed_root)
    target = worktree / "app/main.py"
    target.write_text("worktree changed\n", encoding="utf-8")
    service = _application_service(session, allowed_root, tmp_path / "private-patch-state")

    with pytest.raises(PatchApplicationError, match="differs from the verified patch source"):
        service.apply(patch.id, worktree, patch.id)

    assert list(session.scalars(select(PatchApplication))) == []
    assert target.read_text(encoding="utf-8") == "worktree changed\n"


def test_diff_applicator_rejects_context_that_does_not_match() -> None:
    with pytest.raises(ValueError, match="does not match source"):
        PatchVerificationService._apply_diff(b"value = 9\n", DIFF, "app/main.py")


def test_failed_atomic_replace_keeps_target_unchanged_and_records_failure(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    session, allowed_root, _, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    workspace_path = tmp_path / "review-workspaces" / patch.id
    workspace_path.mkdir(parents=True)
    session.add(
        PatchWorkspace(
            patch_id=patch.id,
            repository_id=finding.repository_id,
            workspace_path=str(workspace_path),
            source_hash=patch.original_hash,
            status="READY_FOR_REVIEW",
        )
    )
    session.commit()
    worktree = _link_worktree(allowed_root)
    target = worktree / "app/main.py"
    replace = os.replace

    def fail_target_replace(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == target:
            raise OSError("simulated atomic replacement failure")
        replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_target_replace)
    service = _application_service(session, allowed_root, tmp_path / "private-patch-state")

    with pytest.raises(PatchApplicationError, match="patch was not applied"):
        service.apply(patch.id, worktree, patch.id)

    application = session.scalar(
        select(PatchApplication).where(PatchApplication.patch_id == patch.id)
    )
    assert application is not None and application.status == "FAILED"
    assert Path(application.backup_path).read_text(encoding="utf-8") == "value = 1\n"
    assert target.read_text(encoding="utf-8") == "value = 1\n"


def test_workspace_rejects_stale_source_hash(
    patch_context: tuple[Session, Path, Path, Path, SecurityFinding],
) -> None:
    session, allowed_root, repository_path, tmp_path, finding = patch_context
    patch = _patch(session, finding, status=PatchStatus.VERIFIED.value)
    (repository_path / "app/main.py").write_text("value = 99\n", encoding="utf-8")
    service = PatchWorkspaceService(
        session,
        RepositoryBoundary([allowed_root]),
        workspace_root=tmp_path / "review-workspaces",
        max_files=100,
        max_workspace_bytes=100_000,
        max_source_file_bytes=10_000,
    )

    with pytest.raises(PatchWorkspaceError, match="source changed"):
        service.create(patch.id)

    assert list(session.scalars(select(PatchWorkspace))) == []
