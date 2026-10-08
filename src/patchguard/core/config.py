from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from patchguard.domain.enums import ScanMode


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PATCHGUARD_",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = "development"
    database_url: str = "sqlite:///./patchguard.db"
    allowed_repository_roots: Annotated[list[Path], NoDecode] = Field(
        default_factory=lambda: [Path.cwd()]
    )
    log_level: str = "INFO"
    log_json: bool = True
    scan_mode: ScanMode = ScanMode.REAL
    read_only: bool = True
    max_index_files: int = Field(default=10_000, ge=1, le=100_000)
    max_source_file_bytes: int = Field(default=1_000_000, ge=1_024, le=20_000_000)
    scanner_timeout_seconds: int = Field(default=120, ge=5, le=1_800)
    scanner_output_limit_bytes: int = Field(default=5_000_000, ge=10_000, le=50_000_000)
    bandit_image: str | None = None
    semgrep_image: str | None = None
    pip_audit_image: str | None = None
    secret_fingerprint_key: SecretStr | None = None
    model_base_url: str | None = None
    model_api_key: SecretStr | None = None
    model_name: str | None = None
    model_context_limit_chars: int = Field(default=12_000, ge=1_000, le=100_000)

    @field_validator("allowed_repository_roots", mode="before")
    @classmethod
    def split_roots(cls, value: object) -> object:
        if isinstance(value, str):
            return [part for part in value.split(":") if part]
        return value

    @field_validator("allowed_repository_roots")
    @classmethod
    def normalize_roots(cls, roots: list[Path]) -> list[Path]:
        if not roots:
            raise ValueError("at least one repository root must be configured")
        return [root.expanduser().resolve() for root in roots]

    @model_validator(mode="after")
    def enforce_phase_one_read_only(self) -> "Settings":
        if not self.read_only:
            raise ValueError("Phase 1 only supports read-only repository access")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
