# Phase 1 acceptance criteria

- Python 3.12+ package installs reproducibly with runtime and development dependencies.
- FastAPI and CLI share configuration, repository inspection, and persistence services.
- SQLite schema is managed by Alembic and represents repositories, scans, scanner runs, findings,
  evidence, patch foundations, and verification-run foundations.
- Health, repository registration, scan creation/status, and findings endpoints are tested.
- Repository inspection identifies common Python language/framework/dependency/test/config/container
  metadata without reading secret values or executing repository code.
- Canonical path and symlink checks confine inspection to configured roots.
- Scanner, repository scanner, patch planner, verification engine, and model provider interfaces are
  typed and decoupled from concrete tools.
- Structured logging is configured without repository source or secret values.
- A scan record is created as `PENDING`; Phase 1 reports no fabricated findings.
- Unit and integration tests demonstrate that repository bytes and paths are unchanged.
- Formatter, linter, strict type checker, tests, API smoke test, and Alembic migration pass.

