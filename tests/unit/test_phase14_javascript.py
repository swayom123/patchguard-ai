import json

from patchguard.domain.scanning import ExecutionStatus
from patchguard.repository.indexer import RepositoryIndexer
from patchguard.repository.language_adapters import JavaScriptLanguageAdapter
from patchguard.scanners.dependencies import DependencySecurityScanner
from patchguard.scanners.javascript import JavaScriptSecurityScanner


def test_javascript_adapter_indexes_without_execution(tmp_path):
    source = tmp_path / "src" / "entry.ts"
    source.parent.mkdir()
    source.write_text(
        "import { run } from './worker';\nexport async function start() { await run(); }\n",
        encoding="utf-8",
    )
    result = RepositoryIndexer([JavaScriptLanguageAdapter()]).index(tmp_path)
    assert len(result.files) == 1
    indexed = result.files[0]
    assert indexed.language == "JavaScript/TypeScript"
    assert [symbol.name for symbol in indexed.symbols] == ["start"]
    assert indexed.imports[0].module == "./worker"
    assert indexed.calls[0].callee_expression == "run"


def test_package_json_inventory_is_static_and_covers_dependency_groups(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"express": "^4.18.0"},
                "devDependencies": {"typescript": "5.4.2"},
            }
        ),
        encoding="utf-8",
    )
    result = DependencySecurityScanner().scan(tmp_path, None)
    assert result.status == ExecutionStatus.COMPLETED
    assert [(item.package, item.dependency_group, item.pinned) for item in result.dependencies] == [
        ("express", "production", False),
        ("typescript", "development", True),
    ]


def test_package_lock_inventory_includes_scoped_and_transitive_versions(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "sample",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "sample", "version": "1.0.0"},
                    "node_modules/left-pad": {"version": "1.2.3"},
                    "node_modules/@scope/pkg": {"version": "2.0.1", "dev": True},
                    "node_modules/nested/node_modules/left-pad": {"version": "1.1.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    result = DependencySecurityScanner().scan(tmp_path, None)

    assert result.status == ExecutionStatus.COMPLETED
    assert [
        (item.package, item.version, item.dependency_group) for item in result.dependencies
    ] == [
        ("left-pad", "1.2.3", "production"),
        ("@scope/pkg", "2.0.1", "development"),
        ("left-pad", "1.1.0", "production"),
    ]


def test_javascript_dynamic_code_rule_is_bounded_and_does_not_execute(tmp_path):
    (tmp_path / "app.js").write_text("const result = eval(input);\n", encoding="utf-8")
    scanner = JavaScriptSecurityScanner(max_files=10, max_file_size_bytes=1000)
    result = scanner.scan(tmp_path, None)
    assert result.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].cwe_id == "CWE-95"
