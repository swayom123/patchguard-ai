"""Auditable finding triage and temporary suppression operations."""

from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from patchguard.domain.enums import FindingStatus
from patchguard.storage.models import (
    FindingSuppression,
    FindingTriageEvent,
    SecurityFinding,
    utc_now,
)

_ALLOWED_TRANSITIONS = {
    FindingStatus.NEW.value: {
        FindingStatus.CONFIRMED.value,
        FindingStatus.LIKELY.value,
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.IGNORED.value,
    },
    FindingStatus.CONFIRMED.value: {
        FindingStatus.NEW.value,
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.IGNORED.value,
        FindingStatus.PATCHED.value,
        FindingStatus.VERIFIED.value,
    },
    FindingStatus.LIKELY.value: {
        FindingStatus.NEW.value,
        FindingStatus.FALSE_POSITIVE.value,
        FindingStatus.IGNORED.value,
        FindingStatus.PATCHED.value,
        FindingStatus.VERIFIED.value,
    },
    FindingStatus.FALSE_POSITIVE.value: {FindingStatus.NEW.value},
    FindingStatus.IGNORED.value: {FindingStatus.NEW.value},
    FindingStatus.PATCHED.value: {FindingStatus.NEW.value, FindingStatus.VERIFIED.value},
    FindingStatus.VERIFIED.value: {FindingStatus.NEW.value},
}


class FindingLifecycleError(ValueError):
    """A finding lifecycle change is not valid for its current state."""


class FindingLifecycleService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def triage(
        self, finding_id: str, new_status: FindingStatus, note: str
    ) -> FindingTriageEvent | None:
        note = note.strip()
        if not 3 <= len(note) <= 2_000:
            raise FindingLifecycleError("triage note must contain between 3 and 2000 characters")
        finding = self._session.get(SecurityFinding, finding_id)
        if finding is None:
            return None
        if new_status.value not in _ALLOWED_TRANSITIONS.get(finding.status, set()):
            raise FindingLifecycleError(
                f"finding cannot transition from {finding.status} to {new_status.value}"
            )
        event = FindingTriageEvent(
            finding_id=finding.id,
            previous_status=finding.status,
            new_status=new_status.value,
            note=note,
        )
        finding.status = new_status.value
        self._session.add(event)
        self._session.commit()
        self._session.refresh(event)
        return event

    def suppress(
        self, finding_id: str, reason: str, expires_at: datetime | None = None
    ) -> FindingSuppression | None:
        reason = reason.strip()
        if not 3 <= len(reason) <= 2_000:
            raise FindingLifecycleError(
                "suppression reason must contain between 3 and 2000 characters"
            )
        finding = self._session.get(SecurityFinding, finding_id)
        if finding is None:
            return None
        now = utc_now()
        if expires_at is not None:
            if expires_at.tzinfo is None or expires_at.utcoffset() is None:
                raise FindingLifecycleError("suppression expiration must include a timezone")
            expires_at = expires_at.astimezone(now.tzinfo)
            if expires_at <= now:
                raise FindingLifecycleError("suppression expiration must be in the future")
        active = self._active_suppression(finding.id, now)
        if active is not None:
            raise FindingLifecycleError("finding already has an active suppression")
        suppression = FindingSuppression(
            finding_id=finding.id,
            reason=reason,
            expires_at=expires_at,
        )
        self._session.add(suppression)
        self._session.commit()
        self._session.refresh(suppression)
        return suppression

    def unsuppress(self, finding_id: str) -> FindingSuppression | None:
        finding = self._session.get(SecurityFinding, finding_id)
        if finding is None:
            return None
        now = utc_now()
        suppression = self._active_suppression(finding.id, now)
        if suppression is None:
            raise FindingLifecycleError("finding has no active suppression")
        suppression.revoked_at = now
        self._session.commit()
        self._session.refresh(suppression)
        return suppression

    def _active_suppression(self, finding_id: str, now: datetime) -> FindingSuppression | None:
        return self._session.scalar(
            select(FindingSuppression)
            .where(
                FindingSuppression.finding_id == finding_id,
                FindingSuppression.revoked_at.is_(None),
                or_(FindingSuppression.expires_at.is_(None), FindingSuppression.expires_at > now),
            )
            .order_by(FindingSuppression.created_at.desc())
            .limit(1)
        )
