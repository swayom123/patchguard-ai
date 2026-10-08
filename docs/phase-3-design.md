# Phase 3 defensive SAST

## Architecture

```text
pending scan
  -> repository re-authorization
  -> scanner adapters
       -> in-process defensive AST rules
       -> Docker-only Bandit adapter
       -> Docker-only Semgrep adapter
  -> normalized findings
  -> stable fingerprints and exact-location deduplication
  -> evidence records
  -> completed or failed scan state
```

Scanner adapters do not write database records. They return typed results to the orchestration
service, which owns lifecycle transitions and persistence. External adapters receive a
`ScannerRunner`; the production runner accepts a structured request and constructs a fixed Docker
invocation without a shell. Tests inject a fake runner.

## Execution boundary

- Target repositories are canonicalized again immediately before scanning.
- External scanners run only in Docker with a read-only repository mount.
- Network is disabled and CPU, memory, PID, timeout, and output-size limits are mandatory.
- The container root filesystem is read-only with a bounded temporary filesystem.
- Images are explicit configuration and are never pulled automatically.
- Missing Docker or images produce `SKIPPED`; there is no host-execution fallback.
- Repository scripts, hooks, builds, tests, package managers, and CI workflows are never invoked.
- Tool output is transient. Raw output and source snippets are not persisted or logged.
- Scanner-reported paths are untrusted and must resolve to real files inside the repository.

## Normalization and evidence

Every candidate has a scanner, rule ID, category, optional authoritative CWE, original severity,
confidence, repository-relative location, and a bounded generic evidence summary. A stable
fingerprint uses normalized file, line, CWE/category, and title. Findings with the same fingerprint
become one database record with separate evidence rows. Scanner severity is recorded but remains a
preliminary value pending later assessment.

## Acceptance criteria

- Custom Python rules detect narrowly defined unsafe shell, dynamic SQL, and pickle-deserialization
  patterns without generating payloads.
- Bandit and Semgrep JSON adapters normalize safe fixtures and reject malformed or escaping paths.
- Scanner lifecycle states accurately represent completion, skipping, timeout, and failure.
- Output limits, timeouts, network denial, read-only mounts, and command structure are tested.
- Duplicate candidates consolidate while retaining each scanner/rule evidence source.
- No candidate exists without a real repository file and line reference.
- API and CLI can run scans and retrieve scanner-run and evidence information.
- The intentionally vulnerable demo is local, harmless, clearly labeled, and unchanged by scans.

