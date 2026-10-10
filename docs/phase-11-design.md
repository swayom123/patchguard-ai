# Phase 11 — patch lifecycle hardening and validation

Phase 11 closes the validation gap across review-only patch planning (6), proposed patch
generation (7), isolated verification (8), review workspaces (9), and guarded linked-worktree
promotion and rollback (10). It does not add new patch behavior; it establishes automated evidence
that the existing lifecycle preserves repository boundaries and reports honest states.

The test suite covers constrained plans and diffs, path and source-hash checks, verification's
`REVIEW_REQUIRED` state when prerequisites are absent, bounded review-workspace creation, explicit
worktree confirmation, private backups, successful rollback, refusal to overwrite intervening
edits, and migration coverage through the current schema head. API integration covers plan
creation/retrieval and honest verification status without requiring Docker or a model provider.

## Acceptance criteria

- Unit tests cover positive and negative cases for patch planning, generation, verification,
  workspace materialization, application, and rollback.
- Integration tests cover the patch planning and verification API contract without external
  services.
- Filesystem tests prove rejected operations leave the registered checkout and selected worktree
  unchanged, except for the one explicitly patched target after confirmation.
- Rollback restores only an unchanged applied target and refuses to clobber later edits.
- A clean database upgrades through Alembic head and contains the current patch lifecycle tables.
- Ruff formatting/linting and strict mypy pass; the full local pytest suite passes.
- No tests execute target-repository code on the host, call a real model endpoint, or require a
  Docker daemon.
