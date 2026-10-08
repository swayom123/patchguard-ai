from enum import StrEnum


class ScanMode(StrEnum):
    REAL = "real"
    DEMO = "demo"
    TEST = "test"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScannerRunStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class FindingStatus(StrEnum):
    NEW = "NEW"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    PATCHED = "PATCHED"
    VERIFIED = "VERIFIED"
    IGNORED = "IGNORED"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AssessmentClassification(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    UNCERTAIN = "UNCERTAIN"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class PatchStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class VerificationStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
