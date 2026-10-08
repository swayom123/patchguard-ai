# PatchGuard AI

PatchGuard AI is a defensive application-security platform for authorized source repositories.
The current Phase 4 build supplies the safe foundation, read-only Python repository intelligence,
evidence-backed defensive SAST, dependency inventory, redacted secret detection, and framework
configuration checks.

## Safety posture

- Repository content is untrusted data.
- The default mode is read-only; the current build cannot apply patches or execute repository code.
- AST indexing never imports or executes target modules.
- Repository paths must resolve beneath an explicitly allowed root.
- Secrets must never be placed in logs or API responses.
- A newly created scan is `PENDING`; findings appear only after an explicit scanner run.

## Quick start

```bash
uv sync --extra dev
cp .env.example .env
uv run alembic upgrade head
uv run patchguard serve
```

API documentation is available at `http://127.0.0.1:8000/docs`. Useful CLI commands:

```bash
uv run patchguard inspect /absolute/path/to/authorized/repository
uv run patchguard register /absolute/path/to/authorized/repository
uv run patchguard scan /absolute/path/to/authorized/repository
uv run patchguard scan-status SCAN_ID
uv run patchguard findings
uv run patchguard index REPOSITORY_ID
uv run patchguard symbols INDEX_ID
uv run patchguard imports INDEX_ID
uv run patchguard calls INDEX_ID
uv run patchguard scan-run SCAN_ID
uv run patchguard scanner-runs SCAN_ID
uv run patchguard finding FINDING_ID
uv run patchguard dependencies SCAN_ID
```

`inspect` reads metadata without persisting it. `register`, `scan`, and `index` write only to
PatchGuard's database. They never change or execute the target repository.

External scanner images are optional and must already exist locally. PatchGuard does not pull
images or fall back to host execution. When no image is configured, the scanner run is recorded as
`SKIPPED`; the built-in AST scanner remains available.

## Development checks

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
```

See [architecture](docs/architecture.md), [security model](docs/security-model.md),
[Phase 3 design](docs/phase-3-design.md), and [Phase 4 design](docs/phase-4-design.md).

## Repository intelligence API

- `GET /repositories/{id}` returns the stored profile.
- `POST /repositories/{id}/indexes` creates an immutable read-only index snapshot.
- `GET /indexes/{id}` returns index status and counts.
- `GET /indexes/{id}/symbols` returns classes, functions, and methods.
- `GET /indexes/{id}/imports` returns imports and resolved internal file dependencies.
- `GET /indexes/{id}/calls` returns conservative call edges.
- `GET /indexes/{id}/issues` returns syntax, encoding, size, and unsupported-language states.
- `POST /scans/{id}/run` runs approved defensive scanners.
- `GET /scans/{id}/scanner-runs` returns exact tool lifecycle states.
- `GET /scans/{id}/dependencies` returns the static dependency inventory for that scan.
- `GET /findings/{id}` returns a normalized finding with all supporting evidence.
