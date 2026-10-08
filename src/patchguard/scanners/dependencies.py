"""Offline-only Python dependency manifest inspection.

This module deliberately parses text and TOML only. It never invokes a package
manager, resolves dependencies, or contacts an advisory service.
"""

from __future__ import annotations

import re
import time
import tomllib
from pathlib import Path

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import (
    DependencyObservation,
    ExecutionStatus,
    NormalizedFinding,
    ScannerAdapterResult,
)
from patchguard.execution.runner import ScannerRunner
from patchguard.scanners.base import ScannerAdapter

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(==|>=|<=|~=|>|<)?\s*([^\s;#]+)?")


class DependencySecurityScanner(ScannerAdapter):
    """Inventories direct dependencies and flags only unpinned direct requirements."""

    name = "patchguard-dependencies"
    execution_mode = "in-process"

    def scan(self, repository: Path, runner: ScannerRunner) -> ScannerAdapterResult:
        del runner
        started = time.monotonic()
        observations: list[DependencyObservation] = []
        findings: list[NormalizedFinding] = []
        try:
            for manifest in ("requirements.txt", "requirements-dev.txt", "constraints.txt"):
                path = repository / manifest
                if path.is_file():
                    observations.extend(self._requirements(repository, path))
            pyproject = repository / "pyproject.toml"
            if pyproject.is_file():
                observations.extend(self._pyproject(repository, pyproject))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            return ScannerAdapterResult(
                scanner=self.name,
                status=ExecutionStatus.FAILED,
                failure_reason="dependency manifest could not be parsed",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        for item in observations:
            if item.pinned:
                continue
            findings.append(
                NormalizedFinding(
                    scanner=self.name,
                    rule_id="patchguard.dependencies.unpinned-direct-requirement",
                    title="Unpinned direct dependency",
                    description=(
                        "A direct dependency does not use an exact version pin; reproducible "
                        "security review and advisory matching may be weakened."
                    ),
                    category="dependency-security",
                    cwe_id=None,
                    cwe_name=None,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=item.manifest_path,
                    line_start=item.line or 1,
                    line_end=item.line or 1,
                    code_reference=None,
                    evidence_summary=(
                        "Static manifest inspection found a non-exact direct requirement."
                    ),
                    evidence_details={
                        "package": item.package,
                        "version": item.version or "unbounded",
                    },
                )
            )
        return ScannerAdapterResult(
            scanner=self.name,
            status=ExecutionStatus.COMPLETED,
            findings=tuple(findings),
            dependencies=tuple(observations),
            version="1",
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _requirements(repository: Path, path: Path) -> list[DependencyObservation]:
        items: list[DependencyObservation] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            candidate = line.split("#", 1)[0].strip()
            if not candidate or candidate.startswith(("-", ".", "/")):
                continue
            match = _REQUIREMENT.match(candidate)
            if match is None:
                continue
            package, operator, version = match.groups()
            if not package:
                continue
            items.append(
                DependencyObservation(
                    package=package.lower().replace("_", "-"),
                    version=version if operator else None,
                    manifest_path=path.relative_to(repository).as_posix(),
                    line=line_number,
                    dependency_group=None,
                    pinned=operator == "==",
                    source="requirements",
                )
            )
        return items

    @staticmethod
    def _pyproject(repository: Path, path: Path) -> list[DependencyObservation]:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        project = document.get("project", {})
        entries: list[tuple[str, str | None]] = [
            (entry, None) for entry in project.get("dependencies", [])
        ]
        optional = project.get("optional-dependencies", {})
        for group, requirements in optional.items():
            entries.extend((entry, str(group)) for entry in requirements)
        results: list[DependencyObservation] = []
        text_lines = path.read_text(encoding="utf-8").splitlines()
        for entry, group in entries:
            match = _REQUIREMENT.match(str(entry))
            if match is None:
                continue
            package, operator, version = match.groups()
            line = next((i for i, value in enumerate(text_lines, 1) if str(entry) in value), 1)
            results.append(
                DependencyObservation(
                    package=package.lower().replace("_", "-"),
                    version=version if operator else None,
                    manifest_path=path.relative_to(repository).as_posix(),
                    line=line,
                    dependency_group=group,
                    pinned=operator == "==",
                    source="pyproject",
                )
            )
        return results
