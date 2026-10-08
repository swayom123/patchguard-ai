# Security model

## Assets and trust boundaries

Target repositories, including filenames, source, tests, hooks, configuration, and comments, are
untrusted data. PatchGuard configuration, its database, command policy, model instructions, and
execution environment are trusted control-plane assets. Repository text can never grant authority
or alter system instructions.

## Current controls

1. Canonicalize requested paths and allow only existing directories under configured roots.
2. Resolve symlinks before authorization; a link cannot escape an allowed root.
3. Perform metadata inspection with Python filesystem APIs only. Do not invoke Git hooks, build
   scripts, package managers, tests, CI, or repository-provided commands.
4. Default `read_only=true`; startup fails if Phase 1 is configured otherwise.
5. Write only to PatchGuard-owned state (SQLite/logs), never target repositories.
6. Keep scan status honest: creating a record means `PENDING`, not completed or verified.
7. Structure logs and avoid source content, environment values, credentials, and evidence payloads.
8. Return repository-relative metadata names; do not read `.env` values.
9. Parse Python as text/AST only; never import modules or evaluate annotations and decorators.
10. Bound indexing by file count and individual source-file size.
11. Store hashes, locations, names, and structural summaries without storing source bodies.
12. Preserve malformed, oversized, and unsupported inputs as explicit non-success states.
13. Run external scanners only in networkless, read-only, resource-limited Docker containers.
14. Require pre-existing configured images; never pull or fall back to host execution.
15. Treat scanner JSON and reported paths as untrusted data and discard raw source snippets.
16. Store generic, masked evidence linked to exact scanner-run records.
17. Secret scanning is disabled unless an operator configures an HMAC fingerprint key; matching
    values are never persisted, logged, or returned, only a non-reversible fingerprint and
    `[REDACTED]` marker.
18. Dependency/configuration adapters parse static text and AST only; they do not install,
    resolve, import, or execute repository-controlled code.

## Deferred controls

Structured command allowlists, worktree-based patching, model context filtering, and independent
patch review are mandatory in later phases before any repository code execution or modification is
enabled.

## Threats explicitly considered

Path traversal, symlink escape, malicious hooks/build files, prompt injection in repository text,
secret disclosure, arbitrary command execution, false success claims, and unauthorized mutation.
