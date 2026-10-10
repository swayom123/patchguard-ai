# Phase 15 — offline npm advisory matching

Phase 15 extends the operator-managed local advisory snapshot with an explicit ecosystem field and
adds npm matching for exact versions inventoried from root `package.json`. Python snapshots and
PEP 440 behavior remain supported as format version 1; version 2 supports both PyPI and npm.

npm versions are checked with a small, local semver implementation for strict three-part versions
and comparator, caret, and tilde ranges. Unsupported expression forms fail snapshot validation, and
ecosystems never cross-match. Evidence includes ecosystem, exact installed version, affected range,
feed provenance, and snapshot hash. All processing is offline, bounded, and read-only.

At the time Phase 15 was implemented, lockfile/transitive inventory was out of scope. Phase 16 adds
bounded static inspection of npm lockfile versions 1–3. Registry fetching, package-manager
invocation, automatic feed refresh, or semver wildcard/OR/hyphen range support remain excluded.
