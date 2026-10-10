# PatchGuard AI

PatchGuard AI is a defensive application-security platform for authorized source repositories.
The current Phase 16 build supplies the safe foundation, read-only Python and JavaScript/TypeScript repository intelligence,
evidence-backed defensive SAST, dependency inventory and optional offline Python/npm advisory matching,
redacted secret detection, framework configuration checks, evidence-bound assessments, auditable
finding triage/suppression, review-only patch plans, and proposed diffs that
are never applied automatically. Proposed diffs can be verified in an isolated, networkless
container when an operator configures a local test image, then materialized in a separate review
workspace. An operator may explicitly promote a verified patch into a separate Git-linked
worktree, with a private backup and guarded rollback.

## Safety posture

- Repository content is untrusted data.
- The registered repository remains unchanged; proposed patches are tested in isolated Docker,
  reviewed in a separate workspace, and applied only to an explicitly selected linked worktree.
- AST indexing never imports or executes target modules.
- Repository paths must resolve beneath an explicitly allowed root.
- Secrets must never be placed in logs or API responses.
- PatchGuard writes only to its database and explicitly configured patch workspaces/backups; a
  patch reaches a linked worktree only through the explicit `apply-patch` CLI confirmation.
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
uv run patchguard findings --status CONFIRMED
uv run patchguard triage-finding FINDING_ID CONFIRMED --note "Reviewed evidence"
uv run patchguard suppress-finding FINDING_ID --reason "Accepted until upgrade window" \
  --expires-at 2027-01-01T00:00:00Z
uv run patchguard unsuppress-finding FINDING_ID
uv run patchguard plan-patch FINDING_ID
uv run patchguard generate-patch FINDING_ID
uv run patchguard verify-patch PATCH_ID
uv run patchguard patch-workspace PATCH_ID
uv run patchguard apply-patch PATCH_ID --worktree /path/to/linked-worktree --confirm PATCH_ID
uv run patchguard rollback-patch APPLICATION_ID
```

`inspect` reads metadata without persisting it. `register`, `scan`, and `index` write only to
PatchGuard's database. They never change or execute the target repository.

## API security and deployment

Local development binds to `127.0.0.1` and may run without API authentication. For a production
configuration, set `PATCHGUARD_ENVIRONMENT=production` and provide a unique
`PATCHGUARD_API_AUTH_TOKEN` of at least 32 characters. Generate one with
`python -c "import secrets; print(secrets.token_urlsafe(48))"`; keep it in a secret manager or a
permission-restricted environment file, never in source control. Send it as
`Authorization: Bearer <token>`. All API paths except `/health` require it; interactive API docs
are disabled in production. Binding to any non-loopback host also requires the token.

This is a single-operator shared token, not user identity or tenant-level authorization: anyone
holding it has the same API access. Put remote deployments behind TLS and a network firewall, and
use a protected persistent database and backup process. Do not expose the plain HTTP server
directly to an untrusted network.

Dependency advisory matching is offline and optional. Configure a reviewed local snapshot with
`PATCHGUARD_ADVISORY_DATABASE_PATH`; `PATCHGUARD_ADVISORY_MAX_AGE_DAYS` defaults to 30. Only exact
pinned Python requirements are matched against PEP 440 affected-version ranges. Missing or stale
snapshots show `patchguard-advisories` as `SKIPPED`; invalid snapshots show `FAILED`. See the
[advisory snapshot schema](docs/advisory-database.md).

Finding triage changes require a rationale and are retained in history. Active suppressions have a
required reason, may have an expiry, and are excluded from finding lists by default. Use
`include_suppressed=true` in the API or `--include-suppressed` in the CLI to include them.

External scanner images are optional and must already exist locally. PatchGuard does not pull
images or fall back to host execution. When no image is configured, the scanner run is recorded as
`SKIPPED`; the built-in AST scanner remains available.

Patch verification also requires a pre-existing local image configured with
`PATCHGUARD_VERIFICATION_IMAGE`. The image must already contain the repository's test dependencies;
PatchGuard does not install packages or invoke repository-provided test commands.
Creating a review workspace requires `PATCHGUARD_PATCH_WORKSPACE_ROOT` to point outside the target
repository.
Applying requires that path to also be within an allowed repository root and identify a linked Git
worktree. Rollback refuses to overwrite a target whose contents changed after application.

## Development checks

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
```

See [architecture](docs/architecture.md), [security model](docs/security-model.md),
[Phase 3 design](docs/phase-3-design.md), and [Phase 4 design](docs/phase-4-design.md).
See the [Phase 6 design](docs/phase-6-design.md) for review-only patch planning boundaries.
See the [Phase 7 design](docs/phase-7-design.md) for proposed patch generation boundaries.
See the [Phase 8 design](docs/phase-8-design.md) for isolated verification boundaries.
See the [Phase 9 design](docs/phase-9-design.md) for separate patch review workspaces.
See the [Phase 10 design](docs/phase-10-design.md) for explicit linked-worktree promotion and rollback.
See the [Phase 11 design](docs/phase-11-design.md) for patch-lifecycle hardening and validation.
See the [Phase 12 design](docs/phase-12-design.md) for single-operator API authentication.
See the [Phase 13 design](docs/phase-13-design.md) for local advisory matching and finding lifecycle.
See the [Phase 14 design](docs/phase-14-design.md) for JavaScript/TypeScript metadata, dynamic-code checks, and npm manifest inventory.
See the [Phase 15 design](docs/phase-15-design.md) for offline npm advisory matching and the [Phase 16 design](docs/phase-16-design.md) for npm lockfile inventory.

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
- `GET /findings?status=CONFIRMED` filters findings by triage status and excludes active
  suppressions unless `include_suppressed=true` is set.
- `GET /findings/{id}` returns a normalized finding with all supporting evidence.
- `PATCH /findings/{id}/triage` records a reasoned status transition.
- `POST /findings/{id}/suppressions` and `/unsuppressions` manage reversible, optional-expiry
  suppressions.
