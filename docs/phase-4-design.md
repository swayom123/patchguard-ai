# Phase 4 — dependency, secret, and configuration security

Phase 4 adds three read-only, in-process adapters. They parse repository files and Python ASTs only; they never import application code, install dependencies, run package scripts, resolve packages, or make network requests.

- `patchguard-dependencies` inventories direct requirements from `requirements*.txt`, `constraints.txt`, and `pyproject.toml`. Exact pins are recorded, while non-exact direct requirements become low-severity reproducibility findings. Advisory lookups are intentionally deferred until a reviewed offline advisory provider is introduced.
- `patchguard-secrets` requires `PATCHGUARD_SECRET_FINGERPRINT_KEY`. It applies conservative credential/private-key patterns and stores only an HMAC-SHA256 fingerprint plus `[REDACTED]`; candidate values never enter findings, evidence, logs, or API responses. Without that key it is explicitly `SKIPPED`.
- `patchguard-configuration` uses literal AST patterns for FastAPI/Flask-style debug flags and credentialed wildcard CORS. It does not execute settings modules.

Dependency inventory is stored against a scan in `dependency_records` and exposed through `GET /scans/{scan_id}/dependencies` and `patchguard dependencies <scan-id>`. Finding lists now support category, scanner, CWE, severity, and confidence filters.

Optional third-party advisory scanning remains disabled. Any future `pip-audit` integration must require a pre-approved local Docker image with offline advisory data, retain network isolation, and never invoke host package tooling.
