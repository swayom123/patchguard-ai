import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from patchguard.domain.scanning import ExecutionStatus
from patchguard.scanners.advisories import LocalAdvisoryScanner
from patchguard.scanners.dependencies import DependencySecurityScanner


class UnusedRunner:
    pass


def _snapshot(path: Path, *, generated_at: datetime | None = None) -> None:
    payload = {
        "format_version": 1,
        "source": "reviewed-test-feed",
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "advisories": [
            {
                "id": "CVE-2025-12345",
                "package": "urllib3",
                "affected": "<1.26.5",
                "fixed_version": "1.26.5",
                "severity": "HIGH",
                "summary": "Versions before 1.26.5 are affected by a test advisory.",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_local_advisories_match_vulnerable_pins_and_record_provenance(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "urllib3==1.26.1\nurllib3==1.26.5\nother-lib>=1.0\n", encoding="utf-8"
    )
    snapshot = tmp_path / "advisories.json"
    _snapshot(snapshot)

    result = LocalAdvisoryScanner(snapshot).scan(tmp_path, UnusedRunner())  # type: ignore[arg-type]

    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title.startswith("CVE-2025-12345")
    assert finding.severity.value == "HIGH"
    assert finding.line_start == 1
    assert finding.evidence_details is not None
    assert finding.evidence_details["installed_version"] == "1.26.1"
    assert finding.evidence_details["fixed_version"] == "1.26.5"
    assert finding.evidence_details["advisory_source"] == "reviewed-test-feed"
    assert len(finding.evidence_details["advisory_snapshot_sha256"]) == 64


def test_missing_or_stale_snapshot_never_claims_advisory_scan_completed(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.1\n", encoding="utf-8")
    missing = LocalAdvisoryScanner(None).scan(tmp_path, UnusedRunner())  # type: ignore[arg-type]
    stale_path = tmp_path / "stale.json"
    _snapshot(stale_path, generated_at=datetime.now(UTC) - timedelta(days=45))
    stale = LocalAdvisoryScanner(stale_path, max_age_days=30).scan(
        tmp_path,
        UnusedRunner(),  # type: ignore[arg-type]
    )

    assert missing.status == ExecutionStatus.SKIPPED
    assert "not configured" in (missing.failure_reason or "")
    assert stale.status == ExecutionStatus.SKIPPED
    assert "stale" in (stale.failure_reason or "")


def test_invalid_snapshot_and_escaping_dependency_manifest_are_failed(tmp_path: Path) -> None:
    snapshot = tmp_path / "invalid.json"
    snapshot.write_text('{"format_version": 9}', encoding="utf-8")
    invalid = LocalAdvisoryScanner(snapshot).scan(tmp_path, UnusedRunner())  # type: ignore[arg-type]

    repository = tmp_path / "repo"
    repository.mkdir()
    outside_manifest = tmp_path / "outside-requirements.txt"
    outside_manifest.write_text("urllib3==1.26.1\n", encoding="utf-8")
    (repository / "requirements.txt").symlink_to(outside_manifest)
    dependency_result = DependencySecurityScanner().scan(
        repository,
        UnusedRunner(),  # type: ignore[arg-type]
    )

    assert invalid.status == ExecutionStatus.FAILED
    assert dependency_result.status == ExecutionStatus.FAILED


def test_npm_advisories_match_semver_without_cross_matching_python(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "test", "version": "1.0.0"},
                    "node_modules/left-pad": {"version": "1.2.3"},
                    "node_modules/other": {"version": "2.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    snapshot = tmp_path / "advisories-v2.json"
    snapshot.write_text(
        json.dumps(
            {
                "format_version": 2,
                "source": "reviewed-npm-feed",
                "generated_at": datetime.now(UTC).isoformat(),
                "advisories": [
                    {
                        "id": "CVE-2025-12345",
                        "ecosystem": "npm",
                        "package": "left-pad",
                        "affected": ">=1.0.0 <2.0.0",
                        "fixed_version": "2.0.0",
                        "severity": "HIGH",
                        "summary": "A reviewed npm test advisory.",
                    },
                    {
                        "id": "CVE-2025-67890",
                        "ecosystem": "pypi",
                        "package": "left-pad",
                        "affected": "<2.0",
                        "severity": "LOW",
                        "summary": "Must not match npm packages.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = LocalAdvisoryScanner(snapshot).scan(tmp_path, UnusedRunner())  # type: ignore[arg-type]

    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.evidence_details is not None
    assert finding.evidence_details["ecosystem"] == "npm"
    assert finding.evidence_details["installed_version"] == "1.2.3"


def test_npm_range_subset_rejects_unsupported_or_malformed_ranges(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/pkg": {"version": "1.2.3"}},
            }
        ),
        encoding="utf-8",
    )
    snapshot = tmp_path / "unsupported-range.json"
    payload = {
        "format_version": 2,
        "source": "reviewed-test-feed",
        "generated_at": datetime.now(UTC).isoformat(),
        "advisories": [
            {
                "id": "CVE-2025-12345",
                "ecosystem": "npm",
                "package": "pkg",
                "affected": "1.x",
                "severity": "HIGH",
                "summary": "Unsupported range forms must fail closed.",
            }
        ],
    }
    snapshot.write_text(json.dumps(payload), encoding="utf-8")

    result = LocalAdvisoryScanner(snapshot).scan(tmp_path, UnusedRunner())  # type: ignore[arg-type]

    assert result.status == ExecutionStatus.FAILED
