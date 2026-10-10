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
5. Write only to PatchGuard-owned state and explicitly configured review workspaces by default;
   promotion requires the separately guarded CLI workflow below.
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
19. Patch generation re-authorizes the repository, constrains the target file beneath its root,
    bounds source context, refuses contexts matching known credential/private-key patterns, and
    stores only a proposed diff with the original source hash. It never applies that diff.
20. Patch verification re-authorizes the repository, checks the original source hash, applies the
    diff only to a bounded temporary snapshot, excludes Git metadata and likely secret files, and
    invokes fixed test commands in a pre-existing networkless Docker image with a read-only mount.
21. A verified patch can be materialized only in a separately configured PatchGuard workspace
    outside the registered repository; it rechecks the source hash and excludes Git metadata and
    likely secrets.
22. Applying requires an exact patch-ID confirmation, a recorded review workspace, and an
    authorized Git-linked worktree distinct from the registered checkout. It rechecks the source
    hash, creates a private byte-for-byte backup, and atomically replaces only the patch target.
    Rollback requires both the current applied hash and backup source hash to match recorded values.
23. Production configuration requires a high-entropy bearer token; every API path except health
    checks it using a constant-time comparison. Interactive API documentation is disabled in
    production. CLI binding beyond loopback is refused unless an API token is configured.
24. Dependency advisory matching uses only an operator-configured, size-limited local snapshot;
    freshness, schema, and source hash are recorded and no runtime network lookup is performed.
    Dependency manifests are bounded and cannot be followed through symlinks outside the
    repository.
25. Triage changes require a rationale and are appended to status history. Suppressions require a
    reason, may expire, can be revoked, and are excluded from findings lists only while active.

## Deferred controls

Direct application to the registered repository remains disabled. Patch promotion is local-CLI
only; the HTTP API has no write route for it. A linked worktree must itself be under an allowed
root. Operators remain responsible for reviewing the diff before running the explicit apply
command. Model context filtering must also be expanded before sending broader repository content to
a provider. Verification runs only fixed test commands in an isolated container. API authentication
is a single shared operator token, not multi-user identity, per-repository authorization, or
tenant isolation; remote deployments must supply TLS termination and network controls.

## Threats explicitly considered

Path traversal, symlink escape, malicious hooks/build files, prompt injection in repository text,
secret disclosure, arbitrary command execution, false success claims, and unauthorized mutation.
