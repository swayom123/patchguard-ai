from sqlalchemy import inspect

from patchguard.storage.database import create_database_engine
from patchguard.storage.models import Base


def test_current_metadata_contains_patch_lifecycle_tables() -> None:
    engine = create_database_engine("sqlite://")
    Base.metadata.create_all(engine)

    assert set(inspect(engine).get_table_names()) == {
        "evidence",
        "finding_suppressions",
        "finding_triage_events",
        "call_relations",
        "code_symbols",
        "dependency_records",
        "import_relations",
        "index_parse_issues",
        "indexed_files",
        "patch_applications",
        "patch_workspaces",
        "repositories",
        "repository_indexes",
        "scanner_runs",
        "security_findings",
        "security_assessments",
        "security_patches",
        "security_patch_plans",
        "security_scans",
        "verification_runs",
    }
