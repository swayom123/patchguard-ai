# Phase 7 — proposed patch generation

Phase 7 creates a proposed unified diff for a persisted finding using the configured model
provider. It re-authorizes the repository, resolves the finding's repository-relative file beneath
the authorized root, rejects symlinked paths, and enforces the configured source-file size limit.
Only a bounded excerpt around the finding and persisted finding evidence are sent to the provider.
If that excerpt matches the built-in credential or private-key patterns, generation stops before
the provider is called.

The provider must return a structured proposal with a unified diff and reason. PatchGuard accepts
only a diff whose old and new headers both name the finding's file and that contains a hunk without
additional file metadata. The full source file is hashed and that hash is stored with the diff in
`security_patches`, whose initial status is `PROPOSED`.

Use `POST /findings/{finding_id}/patches` or `patchguard generate-patch FINDING_ID`. Proposed diffs
appear under `patches` in `GET /findings/{finding_id}`. A proposal is not a claim that the diff
applies, passes tests, or is safe to merge. This phase never writes to the target repository or
runs repository code. Isolated verification is handled separately in Phase 8.

## Acceptance criteria

- The repository is re-authorized before source is read, and the target path remains inside it.
- Symlinked, missing, oversized, non-UTF-8, or out-of-range sources are rejected.
- Model context is bounded and repository text is explicitly treated as untrusted data.
- Detected credential/private-key context is not sent to the model; generated secret-like output is
  rejected before persistence.
- Returned diffs target only the finding file and are stored with the source SHA-256 and `PROPOSED`
  status.
- API and CLI expose proposed diffs without applying them or executing repository code.
