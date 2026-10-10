# Modular-monolith architecture

PatchGuard starts as a modular monolith with dependency flow toward domain contracts:

```text
FastAPI / CLI
     | orchestration services
     | repository boundary + metadata inspector
     | domain interfaces
     | SQLAlchemy persistence
SQLite
```

## Modules

- `apps`: HTTP and command-line delivery adapters.
- `core`: configuration, logging, orchestration, and domain-facing protocols.
- `repository`: safe path authorization and read-only repository inspection.
- `repository/language_adapters`: non-executing Python AST and bounded JavaScript/TypeScript metadata adapters.
- `scanners`: built-in AST rules and normalized Bandit/Semgrep adapters.
- `execution`: structured Docker-only external scanner execution policy.
- `patching`, `verification`, `models`: isolated patch review workspace, verification, model
  provider workflows, and explicit promotion to a separate linked worktree; the registered
  repository is not writable.
- `storage`: SQLAlchemy models, engine/session lifecycle, and migrations.

The database stores repository identity, metadata, immutable structural index snapshots, and
lifecycle records.
API schemas deliberately exclude internal absolute-path details from findings evidence unless that
data is already an authorized, repository-relative reference.

## Domain decisions

IDs are UUID strings for portable SQLite/PostgreSQL behavior. Status, severity, and confidence are
string enums. Timestamps are UTC. Scanner evidence is a separate entity so several scanners can
support one finding. The API can create patch plans, proposed diffs, verification records, and
review workspaces. Applying and rolling back a patch is a separate, explicit local CLI workflow
for a linked worktree; there is no API write route for that operation.

Repository inspection is injected behind `RepositoryScanner`; future language adapters can extend
metadata without changing API orchestration. Scanner, planner, model provider, and verification
interfaces use typed request/response objects rather than shell strings.

## Current phase boundaries

Phase 11 includes read-only Python indexing, defensive SAST, dependency/secret/configuration scans,
evidence-bound model assessments, review-only patch plans, proposed diffs, isolated verification,
and separate patch review workspaces. Verification runs a fixed test command in a configured
networkless Docker container. An operator can explicitly apply a verified patch to a separate
Git-linked worktree after review; a private backup and guarded rollback are recorded. The
registered repository remains unchanged. Phase 11 adds lifecycle regression coverage and validates
the schema through the current migration head.

Phase 12 adds single-operator bearer-token authentication to the HTTP API. Production requires a
configured token and disables interactive API documentation; non-loopback CLI binds require a
token as well. User accounts and tenant-level access control remain future work.

Phase 13 matches exact pinned Python dependencies against a configured local PEP 440 advisory
snapshot and adds auditable finding triage and suppression records. Advisory matching makes no
network calls; freshness and malformed snapshot states are surfaced in scanner runs.

Phase 14 adds heuristic JavaScript/TypeScript structural metadata, a narrow dynamic-code source
rule, and static inventory of npm dependencies declared in `package.json`. It does not run Node,
install packages, resolve npm lockfiles, or match Node packages against the Python advisory database.

Phase 15 extends local snapshots to format version 2 with explicit `pypi`/`npm` ecosystems. It
matches pinned root-manifest npm versions using a documented, conservative semver subset, without
network access or package-manager execution. Version 1 snapshots remain PyPI-only.

Phase 16 reads npm `package-lock.json` versions 1–3 as bounded static JSON, including transitive
package versions, and includes those observations in local npm advisory matching. Yarn and pnpm
lockfiles remain unsupported.
