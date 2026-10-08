from pathlib import Path
from typing import Any

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import NormalizedFinding
from patchguard.scanners.external import JsonExternalScanner
from patchguard.scanners.normalization import normalize_reported_path, safe_identifier
from patchguard.scanners.rules import RULES_BY_CANONICAL_ID, RuleDescriptor


class SemgrepScanner(JsonExternalScanner):
    name = "semgrep"
    command = (
        "semgrep",
        "scan",
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        "--config",
        "/rules/python-security.yml",
        "/workspace",
    )

    def __init__(self, *, image: str | None, timeout_seconds: int, output_limit_bytes: int) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self.rules_directory = Path(__file__).parent / "rules"

    def normalize(self, repository: Path, payload: Any) -> list[NormalizedFinding]:
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("invalid Semgrep payload")
        findings: list[NormalizedFinding] = []
        for item in payload["results"]:
            if not isinstance(item, dict):
                continue
            path = normalize_reported_path(repository, item.get("path"))
            start = item.get("start")
            end = item.get("end")
            if path is None or not isinstance(start, dict) or not isinstance(end, dict):
                continue
            line = self._positive_int(start.get("line"))
            if line is None:
                continue
            rule_id = safe_identifier(item.get("check_id"), fallback="unknown-semgrep-rule")
            descriptor = RULES_BY_CANONICAL_ID.get(rule_id, self._generic_descriptor(item))
            findings.append(
                NormalizedFinding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=descriptor.title,
                    description=descriptor.description,
                    category=descriptor.category,
                    cwe_id=descriptor.cwe_id,
                    cwe_name=descriptor.cwe_name,
                    severity=descriptor.severity,
                    confidence=descriptor.confidence,
                    file_path=path,
                    line_start=line,
                    line_end=self._positive_int(end.get("line")) or line,
                    code_reference=f"{path}:{line}",
                    evidence_summary=f"Semgrep reported rule {rule_id} at this location.",
                )
            )
        return findings

    @staticmethod
    def _positive_int(value: object) -> int | None:
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
        )

    @staticmethod
    def _generic_descriptor(item: dict[str, Any]) -> RuleDescriptor:
        raw_extra = item.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        raw_severity = str(extra.get("severity", "INFO")).upper()
        severity = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }.get(raw_severity, Severity.LOW)
        return RuleDescriptor(
            title="Semgrep security finding",
            description="Semgrep reported a security-relevant source pattern.",
            category="static-analysis",
            cwe_id=None,
            cwe_name=None,
            severity=severity,
            confidence=Confidence.MEDIUM,
        )
