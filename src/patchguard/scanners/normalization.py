import hashlib
import re
from pathlib import Path, PurePosixPath

from patchguard.domain.scanning import NormalizedFinding

_SAFE_IDENTIFIER = re.compile(r"[^A-Za-z0-9_.:/-]+")


def safe_identifier(value: object, *, fallback: str, limit: int = 200) -> str:
    if not isinstance(value, str):
        return fallback
    cleaned = _SAFE_IDENTIFIER.sub("-", value).strip("-.")[:limit]
    return cleaned or fallback


def normalize_reported_path(repository: Path, reported: object) -> str | None:
    if not isinstance(reported, str) or "\x00" in reported:
        return None
    candidate = reported.replace("\\", "/")
    if candidate.startswith("/workspace/"):
        candidate = candidate.removeprefix("/workspace/")
    elif candidate == "/workspace" or candidate.startswith("/"):
        return None
    pure = PurePosixPath(candidate)
    if not candidate or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    host_path = repository.joinpath(*pure.parts)
    try:
        resolved = host_path.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(repository.resolve()):
        return None
    return resolved.relative_to(repository.resolve()).as_posix()


def finding_fingerprint(finding: NormalizedFinding) -> str:
    identity = "|".join(
        (
            finding.file_path,
            str(finding.line_start),
            finding.cwe_id or finding.category,
            finding.title.lower().strip(),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
