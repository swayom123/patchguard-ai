# Phase 13 — offline advisory matching and finding lifecycle

Phase 13 makes dependency findings actionable without adding a network dependency. A new scanner
matches exact pinned Python requirements against a configured local JSON snapshot of reviewed
advisories. PEP 440 specifiers are used to determine whether an installed version is in an affected
range. The snapshot is limited to 10 MB, must validate against format version 1, and must be within
the configured maximum age. No package manager, external service, Docker image, or transitive
dependency resolver is invoked. See [the snapshot schema](advisory-database.md).

Missing or stale data is reported as `SKIPPED`, invalid data as `FAILED`, and findings record the
snapshot SHA-256, source, generation time, affected range, installed version, and suggested fixed
version. Only exact pins are matched; non-exact or unparseable dependency declarations do not
produce vulnerability claims.

Finding triage is an explicit state transition with a required rationale. Every change records the
previous status, new status, note, and timestamp. Suppression is separate from triage and is
auditable, reason-required, optionally time-bounded, and reversible. Active suppressions are hidden
from result lists by default but can be included explicitly. The API and local CLI expose the same
operations. This version records the operator's rationale, not a user identity, because Phase 12
uses a single shared operator token.

## Acceptance criteria

- Local advisory data is opt-in, size-bounded, schema-validated, freshness-checked, and never
  downloaded automatically.
- Pinned versions inside affected PEP 440 ranges generate evidence-backed dependency findings;
  unaffected pins and unpinned dependencies do not.
- Advisory findings include immutable snapshot provenance and appear in normal scan/findings APIs.
- Stale/missing/invalid snapshots surface as `SKIPPED`/`FAILED`, without claiming a clean advisory
  scan.
- Dependency manifests cannot escape the repository through symlinks.
- Triage state changes follow explicit transitions, require a note, and persist an event history.
- Suppression requires a reason, supports optional expiry and revocation, and is excluded from
  findings lists while active unless explicitly included.
- API and CLI expose triage, suppression, unsuppression, and status filtering.
- Tests cover matching boundaries, malformed/stale feeds, path escape, transition errors,
  suppression expiry/revocation, migration, and API/CLI persistence.
