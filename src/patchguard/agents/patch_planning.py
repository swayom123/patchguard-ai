"""Create review-only patch plans from persisted finding evidence."""

import json
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from patchguard.storage.models import SecurityAssessment, SecurityFinding, SecurityPatchPlan


class PatchPlanningAgent:
    """Build a constrained plan without reading or changing repository files."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def plan(self, finding_id: str) -> SecurityPatchPlan | None:
        finding = self._session.get(SecurityFinding, finding_id)
        if finding is None:
            return None

        assessment = self._session.scalar(
            select(SecurityAssessment)
            .where(SecurityAssessment.finding_id == finding.id)
            .order_by(SecurityAssessment.created_at.desc())
            .limit(1)
        )
        fix = assessment.recommended_fix if assessment else finding.description
        context = {
            "finding_id": finding.id,
            "fingerprint": finding.fingerprint,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "category": finding.category,
            "cwe_id": finding.cwe_id,
            "evidence": [
                {
                    "scanner": evidence.scanner,
                    "rule_id": evidence.rule_id,
                    "summary": evidence.summary,
                    "source_reference": evidence.source_reference,
                }
                for evidence in finding.evidence
            ],
            "assessment_id": assessment.id if assessment else None,
            "recommended_fix": fix,
        }
        context_digest = sha256(
            json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        plan = SecurityPatchPlan(
            finding_id=finding.id,
            # The planner takes the target only from the persisted scanner location.
            files_to_modify=[finding.file_path],
            strategy=(
                f"Review the evidence at {finding.file_path}"
                f"{':' + str(finding.line_start) if finding.line_start else ''}; "
                f"apply the narrowest change that addresses the finding. {fix}"
            ),
            behavioral_change=(
                "Reject or safely handle the input or configuration condition identified by the "
                "finding while preserving valid application behavior."
            ),
            compatibility_risks=[
                "Callers that rely on the unsafe behavior may need an explicit compatibility "
                "decision."
            ],
            tests_required=[
                "Add a focused regression test for the reported condition and retain coverage for "
                "valid behavior."
            ],
            rollback_plan=(
                "Review the change in version control and revert the reviewed patch if the "
                "regression test or compatibility checks fail."
            ),
            context_digest=context_digest,
        )
        self._session.add(plan)
        self._session.commit()
        self._session.refresh(plan)
        return plan
