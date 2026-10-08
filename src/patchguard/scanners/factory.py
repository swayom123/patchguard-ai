from patchguard.core.config import Settings
from patchguard.scanners.bandit import BanditScanner
from patchguard.scanners.base import ScannerAdapter
from patchguard.scanners.configuration import ConfigurationScanner
from patchguard.scanners.custom_python import CustomPythonScanner
from patchguard.scanners.dependencies import DependencySecurityScanner
from patchguard.scanners.secrets import SecretScanner
from patchguard.scanners.semgrep import SemgrepScanner


def build_scanners(settings: Settings) -> list[ScannerAdapter]:
    return [
        CustomPythonScanner(
            max_files=settings.max_index_files,
            max_file_size_bytes=settings.max_source_file_bytes,
        ),
        DependencySecurityScanner(),
        ConfigurationScanner(
            max_files=settings.max_index_files,
            max_file_size_bytes=settings.max_source_file_bytes,
        ),
        SecretScanner(
            fingerprint_key=(
                settings.secret_fingerprint_key.get_secret_value()
                if settings.secret_fingerprint_key is not None
                else None
            ),
            max_files=settings.max_index_files,
            max_file_size_bytes=settings.max_source_file_bytes,
        ),
        BanditScanner(
            image=settings.bandit_image,
            timeout_seconds=settings.scanner_timeout_seconds,
            output_limit_bytes=settings.scanner_output_limit_bytes,
        ),
        SemgrepScanner(
            image=settings.semgrep_image,
            timeout_seconds=settings.scanner_timeout_seconds,
            output_limit_bytes=settings.scanner_output_limit_bytes,
        ),
    ]
