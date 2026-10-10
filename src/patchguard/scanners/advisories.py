"""Match pinned dependencies against a local, operator-managed advisory snapshot."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import (
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter
from patchguard.scanners.dependencies import DependencySecurityScanner

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_NPM_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")
_MAX_ADVISORY_DATABASE_BYTES = 10_000_000
_NPM_VERSION = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


class LocalAdvisory(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(min_length=3, max_length=100)
    ecosystem: Literal["pypi", "npm"] = "pypi"
    package: str = Field(min_length=1, max_length=255)
    affected: str = Field(min_length=1, max_length=500)
    fixed_version: str | None = Field(default=None, max_length=100)
    severity: Severity
    summary: str = Field(min_length=1, max_length=2_000)

    @field_validator("package")
    @classmethod
    def validate_package(cls, package: str, info: ValidationInfo) -> str:
        ecosystem = info.data.get("ecosystem", "pypi")
        valid = _NPM_PACKAGE_NAME if ecosystem == "npm" else _PACKAGE_NAME
        if not valid.fullmatch(package.casefold()):
            raise ValueError("invalid advisory package name")
        normalized = package.casefold()
        return normalized if ecosystem == "npm" else normalized.replace("_", "-").replace(".", "-")

    @field_validator("id")
    @classmethod
    def validate_identifier(cls, identifier: str) -> str:
        if not re.fullmatch(
            r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})",
            identifier,
            re.I,
        ):
            raise ValueError("advisory ID must be a CVE or GitHub Security Advisory ID")
        return identifier.upper()

    @field_validator("affected")
    @classmethod
    def validate_specifier(cls, affected: str, info: ValidationInfo) -> str:
        if info.data.get("ecosystem", "pypi") == "npm":
            if not _valid_npm_range(affected):
                raise ValueError("affected must be a supported npm semver range")
            return affected
        try:
            SpecifierSet(affected)
        except InvalidSpecifier as exc:
            raise ValueError("affected must be a valid PEP 440 specifier set") from exc
        return affected


class LocalAdvisoryDatabase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    format_version: int = Field(ge=1, le=2)
    source: str = Field(min_length=1, max_length=200)
    generated_at: datetime
    advisories: list[LocalAdvisory] = Field(max_length=100_000)

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, generated_at: datetime) -> datetime:
        if generated_at.tzinfo is None or generated_at.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        return generated_at.astimezone(UTC)

    @model_validator(mode="after")
    def reject_duplicate_ids(self) -> LocalAdvisoryDatabase:
        identifiers = [advisory.id for advisory in self.advisories]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("advisory IDs must be unique within a snapshot")
        if self.format_version == 1 and any(item.ecosystem != "pypi" for item in self.advisories):
            raise ValueError("format version 1 supports only PyPI advisories")
        return self


class LocalAdvisoryScanner(ScannerAdapter):
    """Read-only advisory matching; no network, package manager, or code execution."""

    name = "patchguard-advisories"
    execution_mode = "in-process"

    def __init__(self, database_path: Path | None, *, max_age_days: int = 30) -> None:
        self._database_path = database_path
        self._max_age_days = max_age_days

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        started = time.monotonic()
        if self._database_path is None:
            return self._result(
                ExecutionStatus.SKIPPED, started, "local advisory snapshot is not configured"
            )
        try:
            database_path = self._database_path.expanduser().resolve(strict=True)
            if (
                not database_path.is_file()
                or database_path.stat().st_size > _MAX_ADVISORY_DATABASE_BYTES
            ):
                raise ValueError("advisory database is not a bounded regular file")
            with database_path.open("rb") as advisory_stream:
                raw = advisory_stream.read(_MAX_ADVISORY_DATABASE_BYTES + 1)
            if len(raw) > _MAX_ADVISORY_DATABASE_BYTES:
                raise ValueError("advisory database exceeds the size limit")
            database = LocalAdvisoryDatabase.model_validate_json(raw)
        except (OSError, ValueError, ValidationError):
            return self._result(
                ExecutionStatus.FAILED, started, "local advisory snapshot is invalid"
            )

        now = datetime.now(UTC)
        if database.generated_at > now + timedelta(minutes=5):
            return self._result(
                ExecutionStatus.FAILED, started, "local advisory snapshot date is invalid"
            )
        if now - database.generated_at > timedelta(days=self._max_age_days):
            return self._result(
                ExecutionStatus.SKIPPED, started, "local advisory snapshot is stale"
            )

        inventory = DependencySecurityScanner().scan(repository, runner)
        if inventory.status != ExecutionStatus.COMPLETED:
            return self._result(
                ExecutionStatus.FAILED, started, "dependency manifests could not be read"
            )
        advisories_by_package: dict[str, list[LocalAdvisory]] = {}
        for advisory in database.advisories:
            advisories_by_package.setdefault(advisory.package, []).append(advisory)

        findings: list[NormalizedFinding] = []
        digest = sha256(raw).hexdigest()
        for dependency in inventory.dependencies:
            if not dependency.pinned or dependency.version is None:
                continue
            installed: Version | None = None
            if dependency.source not in {"npm-package-json", "npm-package-lock"}:
                try:
                    installed = Version(dependency.version)
                except InvalidVersion:
                    continue
            package = (
                dependency.package.casefold()
                if dependency.source in {"npm-package-json", "npm-package-lock"}
                else dependency.package.casefold().replace("_", "-").replace(".", "-")
            )
            for advisory in advisories_by_package.get(package, []):
                if advisory.ecosystem == "npm":
                    if dependency.source not in {
                        "npm-package-json",
                        "npm-package-lock",
                    } or not _npm_satisfies(dependency.version, advisory.affected):
                        continue
                elif (
                    dependency.source in {"npm-package-json", "npm-package-lock"}
                    or installed is None
                    or installed not in SpecifierSet(advisory.affected)
                ):
                    continue
                findings.append(
                    NormalizedFinding(
                        scanner=self.name,
                        rule_id=f"patchguard.advisories.{advisory.id.lower()}",
                        title=f"{advisory.id}: vulnerable dependency {dependency.package}",
                        description=advisory.summary,
                        category="dependency-vulnerability",
                        cwe_id=None,
                        cwe_name=None,
                        severity=advisory.severity,
                        confidence=Confidence.HIGH,
                        file_path=dependency.manifest_path,
                        line_start=dependency.line or 1,
                        line_end=dependency.line or 1,
                        code_reference=None,
                        evidence_summary=(
                            f"Pinned version matched the advisory's affected "
                            f"{'npm semver' if advisory.ecosystem == 'npm' else 'PEP 440'} "
                            "version range in the configured local snapshot."
                        ),
                        evidence_details={
                            "advisory_id": advisory.id,
                            "package": dependency.package,
                            "ecosystem": advisory.ecosystem,
                            "installed_version": dependency.version,
                            "affected_specifier": advisory.affected,
                            "fixed_version": advisory.fixed_version or "unknown",
                            "advisory_source": database.source,
                            "advisory_snapshot_generated_at": database.generated_at.isoformat(),
                            "advisory_snapshot_sha256": digest,
                        },
                    )
                )
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(findings),
            version=f"local-snapshot:{digest[:16]}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _result(
        status: ExecutionStatus, started: float, failure_reason: str
    ) -> ScannerAdapterResult:
        return ScannerAdapterResult(
            scanner=LocalAdvisoryScanner.name,
            status=status,
            failure_reason=failure_reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def _npm_satisfies(version: str, expression: str) -> bool:
    """Match the deliberately bounded npm comparator/caret/tilde range subset."""
    parsed_version = _parse_npm_version(version)
    if parsed_version is None or "||" in expression or " - " in expression:
        return False
    clauses: list[tuple[str, tuple[int, int, int, tuple[str, ...]]]] = []
    for raw in expression.split():
        match = re.fullmatch(r"(\^|~|>=|<=|>|<|=)?(.+)", raw)
        if match is None:
            return False
        operator, value = match.groups()
        bound = _parse_npm_version(value)
        if bound is None:
            return False
        if operator in {"^", "~"}:
            clauses.append((">=", bound))
            major, minor, patch, _ = bound
            if operator == "~":
                upper = (major, minor + 1, 0, ())
            elif major > 0:
                upper = (major + 1, 0, 0, ())
            elif minor > 0:
                upper = (0, minor + 1, 0, ())
            else:
                upper = (0, 0, patch + 1, ())
            clauses.append(("<", upper))
        else:
            clauses.append((operator or "=", bound))
    if not clauses:
        return False
    for operator, bound in clauses:
        compared = _compare_npm_versions(parsed_version, bound)
        if not {
            "=": compared == 0,
            ">": compared > 0,
            ">=": compared >= 0,
            "<": compared < 0,
            "<=": compared <= 0,
        }[operator]:
            return False
    return True


def _valid_npm_range(expression: str) -> bool:
    if not expression or "||" in expression or " - " in expression:
        return False
    parts = expression.split()
    if not parts:
        return False
    for part in parts:
        match = re.fullmatch(r"(\^|~|>=|<=|>|<|=)?(.+)", part)
        if match is None or _parse_npm_version(match.group(2)) is None:
            return False
    return True


def _parse_npm_version(value: str) -> tuple[int, int, int, tuple[str, ...]] | None:
    match = _NPM_VERSION.fullmatch(value)
    if match is None:
        return None
    major, minor, patch, prerelease = match.groups()
    prerelease_parts = tuple(prerelease.split(".")) if prerelease else ()
    if any(
        not item or (item.isdigit() and len(item) > 1 and item.startswith("0"))
        for item in prerelease_parts
    ):
        return None
    return (
        int(major),
        int(minor),
        int(patch),
        prerelease_parts,
    )


def _compare_npm_versions(
    left: tuple[int, int, int, tuple[str, ...]],
    right: tuple[int, int, int, tuple[str, ...]],
) -> int:
    if left[:3] != right[:3]:
        return (left[:3] > right[:3]) - (left[:3] < right[:3])
    left_pre, right_pre = left[3], right[3]
    if not left_pre or not right_pre:
        return (not left_pre) - (not right_pre)
    for first, second in zip(left_pre, right_pre, strict=False):
        if first == second:
            continue
        first_numeric, second_numeric = first.isdigit(), second.isdigit()
        if first_numeric and second_numeric:
            return (int(first) > int(second)) - (int(first) < int(second))
        if first_numeric != second_numeric:
            return -1 if first_numeric else 1
        return (first > second) - (first < second)
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))
