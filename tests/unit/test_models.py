from sqlalchemy import inspect

from patchguard.storage.database import create_database_engine
from patchguard.storage.models import Base


def test_phase_one_schema_contains_required_tables() -> None:
    engine = create_database_engine("sqlite://")
    Base.metadata.create_all(engine)

    assert set(inspect(engine).get_table_names()) == {
        "evidence",
        "call_relations",
        "code_symbols",
        "dependency_records",
        "import_relations",
        "index_parse_issues",
        "indexed_files",
        "repositories",
        "repository_indexes",
        "scanner_runs",
        "security_findings",
        "security_assessments",
        "security_patches",
        "security_scans",
        "verification_runs",
    }
