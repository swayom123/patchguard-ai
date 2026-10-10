# Phase 8 — isolated patch verification

Phase 8 verifies a proposed patch against a disposable repository snapshot. It first re-authorizes
the repository and confirms that the finding file still has the SHA-256 recorded at generation
time. It copies a bounded snapshot while excluding Git metadata, virtual environments, symlinks,
and files matching known secret-name or secret-content patterns. The diff is applied to the copy
with a strict single-file unified-diff applicator.

Verification runs only when an operator has configured a pre-existing local Docker image and the
stored repository profile identifies `pytest` or `unittest`. PatchGuard invokes a fixed Python test
command, disables network access, mounts the temporary workspace read-only, limits resources and
output, and runs as the current non-root host UID so the private temporary directory remains
private. It does not pull images or fall back to host execution.

Use `POST /patches/{patch_id}/verify` or `patchguard verify-patch PATCH_ID`; retrieve a run with
`GET /verification-runs/{run_id}`. A run is `VERIFIED` only when the test command exits successfully
in the container. Missing configuration, stale source, unsupported test framework, unsafe or
oversized inputs, and unavailable Docker produce `REVIEW_REQUIRED`. A failing or timed-out test
produces `FAILED`. Raw test output is not persisted. Materializing a verified result for human
review is handled in Phase 9.

## Acceptance criteria

- Verification re-authorizes the repository and rejects a changed source hash.
- The target repository is never changed; the diff is applied only to a bounded temporary copy.
- Snapshot creation rejects symlinks and excludes Git metadata and likely secret files/content.
- Only fixed `pytest` or `unittest` commands run in a configured local Docker image.
- The container has no network, a read-only workspace, resource limits, and a non-root identity.
- Missing prerequisites and unsafe inputs remain explicit `REVIEW_REQUIRED` outcomes.
- Run lifecycle, check results, and generic failure reasons are persisted without raw test output.
