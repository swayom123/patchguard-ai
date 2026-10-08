from dataclasses import dataclass

from patchguard.domain.enums import Confidence, Severity


@dataclass(frozen=True, slots=True)
class RuleDescriptor:
    title: str
    description: str
    category: str
    cwe_id: str | None
    cwe_name: str | None
    severity: Severity
    confidence: Confidence


SUBPROCESS_SHELL = RuleDescriptor(
    title="Unsafe subprocess shell execution",
    description="A subprocess call explicitly enables shell interpretation.",
    category="command-injection",
    cwe_id="CWE-78",
    cwe_name="OS Command Injection",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
)

DYNAMIC_SQL = RuleDescriptor(
    title="Dynamic SQL construction",
    description="A database execution call receives a dynamically constructed string.",
    category="sql-injection",
    cwe_id="CWE-89",
    cwe_name="SQL Injection",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
)

UNSAFE_PICKLE = RuleDescriptor(
    title="Unsafe pickle deserialization",
    description="Python pickle deserialization can execute code from untrusted serialized data.",
    category="unsafe-deserialization",
    cwe_id="CWE-502",
    cwe_name="Deserialization of Untrusted Data",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
)


RULES_BY_CANONICAL_ID = {
    "patchguard.python.subprocess-shell-true": SUBPROCESS_SHELL,
    "patchguard.python.dynamic-sql-execute": DYNAMIC_SQL,
    "patchguard.python.unsafe-pickle": UNSAFE_PICKLE,
}

BANDIT_RULES = {
    "B602": SUBPROCESS_SHELL,
    "B608": DYNAMIC_SQL,
    "B301": UNSAFE_PICKLE,
}
