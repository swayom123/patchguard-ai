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
- `repository/language_adapters`: non-executing language parsers, initially Python AST.
- `scanners`: built-in AST rules and normalized Bandit/Semgrep adapters.
- `execution`: structured Docker-only external scanner execution policy.
- `patching`, `verification`, `models`: contracts for later phases, with no mutation capability.
- `storage`: SQLAlchemy models, engine/session lifecycle, and migrations.

The database stores repository identity, metadata, immutable structural index snapshots, and
lifecycle records.
API schemas deliberately exclude internal absolute-path details from findings evidence unless that
data is already an authorized, repository-relative reference.

## Domain decisions

IDs are UUID strings for portable SQLite/PostgreSQL behavior. Status, severity, and confidence are
string enums. Timestamps are UTC. Scanner evidence is a separate entity so several scanners can
support one finding. Patch and verification tables exist as foundations, but the current API does
not create or apply patches.

Repository inspection is injected behind `RepositoryScanner`; future language adapters can extend
metadata without changing API orchestration. Scanner, planner, model provider, and verification
interfaces use typed request/response objects rather than shell strings.

## Current phase boundaries

Phase 3 parses Python ASTs, records structural intelligence, and creates preliminary SAST findings
from controlled custom rules or optional Docker-isolated Bandit/Semgrep runs. It does not call an AI
model, confirm vulnerabilities, scan dependencies or secrets, create worktrees, generate patches,
or run repository tests. Those remain explicit later-phase capabilities.
