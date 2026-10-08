from pathlib import Path

from patchguard.repository.scanner import LocalRepositoryScanner


def test_detects_python_fastapi_metadata(demo_repository: Path) -> None:
    profile = LocalRepositoryScanner().inspect(demo_repository)

    assert profile.languages == ("Python",)
    assert profile.frameworks == ("FastAPI",)
    assert profile.package_managers == ("pip",)
    assert profile.dependency_files == ("pyproject.toml",)
    assert profile.test_frameworks == ("pytest",)
    assert profile.source_directories == ("app",)
    assert profile.metadata["inspection_mode"] == "read-only"


def test_does_not_follow_manifest_symlink_outside_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    outside_manifest = tmp_path / "outside.toml"
    outside_manifest.write_text('dependencies = ["django"]\n', encoding="utf-8")
    (repository / "pyproject.toml").symlink_to(outside_manifest)

    profile = LocalRepositoryScanner().inspect(repository)

    assert profile.frameworks == ()


def test_detects_ci_infrastructure_and_build_metadata(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    workflows = repository / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text("name: test\n", encoding="utf-8")
    (repository / "main.tf").write_text("# fixture\n", encoding="utf-8")
    (repository / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    profile = LocalRepositoryScanner().inspect(repository)

    assert profile.ci_files == (".github/workflows/test.yml",)
    assert profile.infrastructure_files == ("main.tf",)
    assert profile.build_systems == ("pyproject", "docker")


def test_reads_authorized_worktree_git_metadata_without_git_command(tmp_path: Path) -> None:
    root = tmp_path / "authorized"
    repository = root / "worktree"
    git_dir = root / "main" / ".git" / "worktrees" / "worktree"
    refs = root / "main" / ".git" / "refs" / "heads"
    repository.mkdir(parents=True)
    git_dir.mkdir(parents=True)
    refs.mkdir(parents=True)
    (repository / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (git_dir / "commondir").write_text("../..\n", encoding="ascii")
    (refs / "main").write_text("a" * 40 + "\n", encoding="ascii")

    profile = LocalRepositoryScanner([root]).inspect(repository)

    assert profile.metadata["default_branch"] == "main"
    assert profile.metadata["commit_hash"] == "a" * 40


def test_reads_normal_repository_packed_ref_without_git_command(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    git_dir = repository / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (git_dir / "packed-refs").write_text(f"{'b' * 40} refs/heads/main\n", encoding="ascii")

    profile = LocalRepositoryScanner().inspect(repository)

    assert profile.metadata["default_branch"] == "main"
    assert profile.metadata["commit_hash"] == "b" * 40
