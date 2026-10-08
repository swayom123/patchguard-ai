from pathlib import Path
from typing import Any

from patchguard.domain.enums import Confidence, Severity
from patchguard.domain.scanning import NormalizedFinding
from patchguard.scanners.external import JsonExternalScanner
from patchguard.scanners.normalization import normalize_reported_path, safe_identifier
from patchguard.scanners.rules import BANDIT_RULES, RuleDescriptor


class BanditScanner(JsonExternalScanner):
    name = "bandit"
    command = ("bandit", "-r", "/workspace", "-f", "json", "-q")
    success_exit_codes = (0, 1)

    def __init__(self, *, image: str | None, timeout_seconds: int, output_limit_bytes: int) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes

    def normalize(self, repository: Path, payload: Any) -> list[NormalizedFinding]:
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("invalid Bandit payload")
        findings: list[NormalizedFinding] = []
        for item in payload["results"]:
            if not isinstance(item, dict):
                continue
            path = normalize_reported_path(repository, item.get("filename"))
            line = self._positive_int(item.get("line_number"))
            if path is None or line is None:
                continue
            rule_id = safe_identifier(item.get("test_id"), fallback="unknown-bandit-rule")
            descriptor = BANDIT_RULES.get(rule_id, self._generic_descriptor(item))
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
                    line_end=self._end_line(item.get("line_range"), line),
                    code_reference=f"{path}:{line}",
                    evidence_summary=f"Bandit reported rule {rule_id} at this location.",
                )
            )
        return findings

    @staticmethod
    def _positive_int(value: object) -> int | None:
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
        )

    @classmethod
    def _end_line(cls, value: object, fallback: int) -> int:
        if not isinstance(value, list) or not value:
            return fallback
        return cls._positive_int(value[-1]) or fallback

    @staticmethod
    def _generic_descriptor(item: dict[str, Any]) -> RuleDescriptor:
        severity_value = str(item.get("issue_severity", "LOW")).upper()
        confidence_value = str(item.get("issue_confidence", "LOW")).upper()
        severity = Severity(severity_value) if severity_value in Severity else Severity.LOW
        confidence = (
            Confidence(confidence_value) if confidence_value in Confidence else Confidence.LOW
        )
        return RuleDescriptor(
            title="Bandit security finding",
            description="Bandit reported a security-relevant Python pattern.",
            category="static-analysis",
            cwe_id=None,
            cwe_name=None,
            severity=severity,
            confidence=confidence,
        )
