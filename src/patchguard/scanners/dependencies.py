"""Offline-only Python dependency manifest inspection.

This module deliberately parses text and TOML only. It never invokes a package
manager, resolves dependencies, or contacts an advisory service.
"""

from __future__ import annotations

import json
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
_MAX_MANIFEST_BYTES = 5_000_000
_MAX_LOCKFILE_PACKAGES = 100_000
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")
_NPM_VERSION = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


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
            package_json = repository / "package.json"
            if package_json.is_file():
                observations.extend(self._package_json(repository, package_json))
            package_lock = repository / "package-lock.json"
            if package_lock.is_file():
                observations.extend(self._package_lock(repository, package_lock))
        except (OSError, ValueError, RecursionError):
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
        safe_path = DependencySecurityScanner._safe_manifest(repository, path)
        for line_number, line in enumerate(
            DependencySecurityScanner._read_manifest(safe_path).splitlines(), start=1
        ):
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
        safe_path = DependencySecurityScanner._safe_manifest(repository, path)
        text = DependencySecurityScanner._read_manifest(safe_path)
        document = tomllib.loads(text)
        project = document.get("project", {})
        entries: list[tuple[str, str | None]] = [
            (entry, None) for entry in project.get("dependencies", [])
        ]
        optional = project.get("optional-dependencies", {})
        for group, requirements in optional.items():
            entries.extend((entry, str(group)) for entry in requirements)
        results: list[DependencyObservation] = []
        text_lines = text.splitlines()
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

    @staticmethod
    def _package_json(repository: Path, path: Path) -> list[DependencyObservation]:
        safe_path = DependencySecurityScanner._safe_manifest(repository, path)
        text = DependencySecurityScanner._read_manifest(safe_path)
        document = json.loads(text)
        if not isinstance(document, dict):
            raise ValueError("package.json root must be an object")
        observations: list[DependencyObservation] = []
        for field, group in (
            ("dependencies", "production"),
            ("devDependencies", "development"),
            ("optionalDependencies", "optional"),
            ("peerDependencies", "peer"),
        ):
            dependencies = document.get(field, {})
            if not isinstance(dependencies, dict):
                raise ValueError(f"package.json {field} must be an object")
            for package, version_value in dependencies.items():
                if not isinstance(package, str) or not isinstance(version_value, str):
                    continue
                version = version_value.strip()
                pinned = bool(
                    re.fullmatch(
                        r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
                    )
                )
                observations.append(
                    DependencyObservation(
                        package=package.lower(),
                        version=version or None,
                        manifest_path=path.relative_to(repository).as_posix(),
                        line=None,
                        dependency_group=group,
                        pinned=pinned,
                        source="npm-package-json",
                    )
                )
        return observations

    @staticmethod
    def _package_lock(repository: Path, path: Path) -> list[DependencyObservation]:
        safe_path = DependencySecurityScanner._safe_manifest(repository, path)
        document = json.loads(DependencySecurityScanner._read_manifest(safe_path))
        if not isinstance(document, dict) or document.get("lockfileVersion") not in {1, 2, 3}:
            raise ValueError("unsupported package-lock.json format")
        packages = document.get("packages")
        if isinstance(packages, dict):
            if len(packages) > _MAX_LOCKFILE_PACKAGES:
                raise ValueError("package-lock.json has too many package entries")
            entries = [
                (package_path, metadata)
                for package_path, metadata in packages.items()
                if package_path and isinstance(package_path, str) and isinstance(metadata, dict)
            ]
        elif document["lockfileVersion"] == 1:
            entries = DependencySecurityScanner._legacy_lock_entries(
                document.get("dependencies", {})
            )
            if len(entries) > _MAX_LOCKFILE_PACKAGES:
                raise ValueError("package-lock.json has too many package entries")
        else:
            raise ValueError("package-lock.json packages section is missing")

        observations: list[DependencyObservation] = []
        for package_path, metadata in entries:
            package = metadata.get("name") or DependencySecurityScanner._lock_package_name(
                package_path
            )
            version = metadata.get("version")
            if not isinstance(package, str) or not isinstance(version, str):
                continue
            package = package.casefold()
            version = version.strip()
            if not _NPM_NAME.fullmatch(package):
                continue
            observations.append(
                DependencyObservation(
                    package=package,
                    version=version,
                    manifest_path=path.relative_to(repository).as_posix(),
                    line=None,
                    dependency_group=DependencySecurityScanner._lock_dependency_group(metadata),
                    pinned=bool(_NPM_VERSION.fullmatch(version)),
                    source="npm-package-lock",
                )
            )
        return observations

    @staticmethod
    def _legacy_lock_entries(dependencies: object) -> list[tuple[str, dict[str, object]]]:
        entries: list[tuple[str, dict[str, object]]] = []

        def visit(items: object, prefix: str, depth: int = 0) -> None:
            if depth > 100 or not isinstance(items, dict):
                return
            for name, raw_metadata in items.items():
                if not isinstance(name, str) or not isinstance(raw_metadata, dict):
                    continue
                current = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
                entries.append((current, raw_metadata))
                if len(entries) > _MAX_LOCKFILE_PACKAGES:
                    raise ValueError("package-lock.json has too many package entries")
                visit(raw_metadata.get("dependencies", {}), current, depth + 1)

        visit(dependencies, "")
        return entries

    @staticmethod
    def _lock_package_name(package_path: str) -> str | None:
        marker = "node_modules/"
        if marker not in package_path:
            return None
        name = package_path.rsplit(marker, 1)[1]
        parts = name.split("/")
        if name.startswith("@"):
            return "/".join(parts[:2]) if len(parts) >= 2 else None
        return parts[0] if parts and parts[0] else None

    @staticmethod
    def _lock_dependency_group(metadata: dict[str, object]) -> str:
        if metadata.get("optional") is True:
            return "optional"
        if metadata.get("dev") is True:
            return "development"
        if metadata.get("peer") is True:
            return "peer"
        return "production"

    @staticmethod
    def _safe_manifest(repository: Path, path: Path) -> Path:
        if path.is_symlink():
            raise ValueError("dependency manifest symlinks are not allowed")
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or not resolved.is_relative_to(repository.resolve()):
            raise ValueError("dependency manifest escapes repository")
        if resolved.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ValueError("dependency manifest exceeds the size limit")
        return resolved

    @staticmethod
    def _read_manifest(path: Path) -> str:
        with path.open("rb") as manifest:
            raw = manifest.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise ValueError("dependency manifest exceeds the size limit")
        return raw.decode("utf-8")
