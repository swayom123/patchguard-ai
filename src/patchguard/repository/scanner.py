from pathlib import Path

from patchguard.core.interfaces import RepositoryProfile, RepositoryScanner


class LocalRepositoryScanner(RepositoryScanner):
    """Conservative metadata scanner: names only, no command execution or secret reads."""

    _dependency_files = (
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "Pipfile",
        "uv.lock",
    )
    _config_files = (
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "pytest.ini",
        ".env.example",
        "mypy.ini",
        ".ruff.toml",
    )
    _container_files = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml")
    _source_dirs = ("src", "app", "apps", "patchguard")

    def __init__(self, allowed_roots: list[Path] | None = None) -> None:
        self._allowed_roots = tuple(root.resolve() for root in allowed_roots or [])

    def inspect(self, repository: Path) -> RepositoryProfile:
        top_level = {path.name for path in repository.iterdir()}
        dependency_files = tuple(name for name in self._dependency_files if name in top_level)
        config_files = tuple(name for name in self._config_files if name in top_level)
        container_files = tuple(name for name in self._container_files if name in top_level)
        ci_files = self._ci_files(repository, top_level)
        infrastructure_files = self._infrastructure_files(repository)
        build_systems = self._build_systems(top_level)
        source_directories = tuple(
            name for name in self._source_dirs if (repository / name).is_dir()
        )

        language_counts = self._language_counts(repository)
        python_files = language_counts.get("Python", 0)
        languages = tuple(language for language, count in language_counts.items() if count)
        package_managers = self._package_managers(top_level)
        frameworks = self._frameworks(repository, dependency_files)
        test_frameworks = self._test_frameworks(repository, dependency_files)
        branch, commit_hash = self._git_identity(repository)

        return RepositoryProfile(
            path=repository,
            languages=languages,
            frameworks=frameworks,
            package_managers=package_managers,
            dependency_files=dependency_files,
            test_frameworks=test_frameworks,
            source_directories=source_directories,
            config_files=config_files,
            container_files=container_files,
            ci_files=ci_files,
            infrastructure_files=infrastructure_files,
            build_systems=build_systems,
            metadata={
                "python_file_count": python_files,
                "language_file_counts": language_counts,
                "has_git_metadata": (repository / ".git").exists(),
                "inspection_mode": "read-only",
                "default_branch": branch,
                "commit_hash": commit_hash,
            },
        )

    @staticmethod
    def _count_files(repository: Path, suffix: str) -> int:
        count = 0
        for path in repository.rglob(f"*{suffix}"):
            if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
                continue
            try:
                contained = path.resolve().is_relative_to(repository.resolve())
            except OSError:
                contained = False
            if contained and path.is_file():
                count += 1
        return count

    @classmethod
    def _language_counts(cls, repository: Path) -> dict[str, int]:
        suffixes = {
            "Python": ".py",
            "JavaScript": ".js",
            "TypeScript": ".ts",
            "Java": ".java",
            "Go": ".go",
            "Rust": ".rs",
            "C#": ".cs",
            "PHP": ".php",
        }
        return {
            language: cls._count_files(repository, suffix) for language, suffix in suffixes.items()
        }

    @staticmethod
    def _package_managers(names: set[str]) -> tuple[str, ...]:
        managers: list[str] = []
        if "poetry.lock" in names:
            managers.append("poetry")
        if "Pipfile" in names:
            managers.append("pipenv")
        if {"pyproject.toml", "requirements.txt", "requirements-dev.txt"} & names:
            managers.append("pip")
        if "uv.lock" in names:
            managers.append("uv")
        return tuple(managers)

    @staticmethod
    def _safe_manifest_text(repository: Path, files: tuple[str, ...]) -> str:
        chunks: list[str] = []
        for name in files:
            path = repository / name
            if name not in {"pyproject.toml", "requirements.txt", "Pipfile"}:
                continue
            try:
                if not path.resolve(strict=True).is_relative_to(repository.resolve()):
                    continue
                chunks.append(path.read_text(encoding="utf-8", errors="replace")[:256_000].lower())
            except OSError:
                continue
        return "\n".join(chunks)

    def _frameworks(self, repository: Path, files: tuple[str, ...]) -> tuple[str, ...]:
        text = self._safe_manifest_text(repository, files)
        known = (("fastapi", "FastAPI"), ("django", "Django"), ("flask", "Flask"))
        return tuple(display for marker, display in known if marker in text)

    def _test_frameworks(self, repository: Path, files: tuple[str, ...]) -> tuple[str, ...]:
        text = self._safe_manifest_text(repository, files)
        frameworks: list[str] = []
        if "pytest" in text or (repository / "pytest.ini").exists():
            frameworks.append("pytest")
        if (repository / "tests").is_dir() and not frameworks:
            frameworks.append("unittest")
        return tuple(frameworks)

    def _git_identity(self, repository: Path) -> tuple[str | None, str | None]:
        """Read Git/worktree metadata without invoking Git or hooks."""
        git_marker = repository / ".git"
        git_dir = self._resolve_git_dir(repository, git_marker)
        if git_dir is None:
            return None, None
        head = git_dir / "HEAD"
        try:
            head_resolved = head.resolve(strict=True)
            if not self._is_authorized(head_resolved, repository):
                return None, None
            value = head_resolved.read_text(encoding="ascii", errors="strict").strip()
            if value.startswith("ref: refs/heads/"):
                ref_name = value.removeprefix("ref: ")
                commit = self._read_ref(repository, git_dir, ref_name)
                return ref_name.removeprefix("refs/heads/"), commit or None
            return None, value or None
        except (OSError, UnicodeError):
            return None, None

    def _resolve_git_dir(self, repository: Path, marker: Path) -> Path | None:
        try:
            marker_resolved = marker.resolve(strict=True)
            if not marker_resolved.is_relative_to(repository.resolve()):
                return None
            if marker.is_dir():
                resolved = marker_resolved
            elif marker.is_file():
                value = marker.read_text(encoding="utf-8", errors="strict").strip()
                if not value.startswith("gitdir: "):
                    return None
                target = Path(value.removeprefix("gitdir: "))
                resolved = (
                    target.resolve(strict=True)
                    if target.is_absolute()
                    else (repository / target).resolve(strict=True)
                )
            else:
                return None
            return (
                resolved
                if self._is_authorized(resolved, repository) and resolved.is_dir()
                else None
            )
        except (OSError, UnicodeError):
            return None

    def _read_ref(self, repository: Path, git_dir: Path, ref_name: str) -> str | None:
        roots = [git_dir]
        common = git_dir / "commondir"
        try:
            if common.is_file():
                common_resolved = common.resolve(strict=True)
                if not self._is_authorized(common_resolved, repository):
                    return None
                common_value = common_resolved.read_text(encoding="utf-8", errors="strict").strip()
                common_dir = (git_dir / common_value).resolve(strict=True)
                if self._is_authorized(common_dir, repository):
                    roots.append(common_dir)
        except (OSError, UnicodeError):
            pass
        for root in roots:
            ref_path = root / ref_name
            try:
                resolved = ref_path.resolve(strict=True)
                if self._is_authorized(resolved, repository):
                    return resolved.read_text(encoding="ascii", errors="strict").strip() or None
            except (OSError, UnicodeError):
                pass
            packed_refs = root / "packed-refs"
            try:
                packed_resolved = packed_refs.resolve(strict=True)
                if not self._is_authorized(packed_resolved, repository):
                    continue
                for line in packed_resolved.read_text(
                    encoding="ascii", errors="strict"
                ).splitlines():
                    if line.startswith(("#", "^")) or " " not in line:
                        continue
                    commit, packed_name = line.split(" ", 1)
                    if packed_name == ref_name:
                        return commit
            except (OSError, UnicodeError):
                continue
        return None

    def _is_authorized(self, path: Path, repository: Path) -> bool:
        roots = self._allowed_roots or (repository.resolve(),)
        return any(path == root or path.is_relative_to(root) for root in roots)

    @staticmethod
    def _ci_files(repository: Path, names: set[str]) -> tuple[str, ...]:
        results = [
            name
            for name in (".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile")
            if name in names
        ]
        workflow_dir = repository / ".github" / "workflows"
        if workflow_dir.is_dir() and workflow_dir.resolve().is_relative_to(repository.resolve()):
            for path in sorted(workflow_dir.iterdir()):
                try:
                    if path.suffix in {".yml", ".yaml"} and path.resolve().is_relative_to(
                        repository.resolve()
                    ):
                        results.append(path.relative_to(repository).as_posix())
                except OSError:
                    continue
        return tuple(results)

    @staticmethod
    def _infrastructure_files(repository: Path) -> tuple[str, ...]:
        results: list[str] = []
        for path in repository.rglob("*"):
            if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
                continue
            try:
                if not path.is_file() or not path.resolve().is_relative_to(repository.resolve()):
                    continue
            except OSError:
                continue
            if path.suffix == ".tf" or path.name in {"Chart.yaml", "kustomization.yaml"}:
                results.append(path.relative_to(repository).as_posix())
        return tuple(sorted(results))

    @staticmethod
    def _build_systems(names: set[str]) -> tuple[str, ...]:
        markers = (
            ("pyproject.toml", "pyproject"),
            ("setup.py", "setuptools"),
            ("Makefile", "make"),
            ("Dockerfile", "docker"),
        )
        return tuple(system for marker, system in markers if marker in names)
