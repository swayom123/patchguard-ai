# Phase 10 — guarded linked-worktree promotion

Phase 10 adds an explicit local CLI path to promote an independently reviewed, successfully
verified patch from its PatchGuard review record into a user-selected Git-linked worktree. It does
not modify the registered checkout and adds no HTTP write endpoint.

Run `patchguard apply-patch PATCH_ID --worktree PATH --confirm PATCH_ID`. The patch must be
`VERIFIED`, and a Phase 9 review workspace must already be recorded. The selected worktree must be
under a configured allowed root, differ from the registered repository, and have a valid `.git`
file pointing at linked-worktree Git metadata. PatchGuard does not invoke Git or run hooks.

The target file path is taken only from the stored patch. Paths and symlinks are checked, the source
hash is revalidated, and a private byte-for-byte backup is written under
`PATCHGUARD_PATCH_WORKSPACE_ROOT/backups/` before an atomic replacement. The CLI prints the
application ID and backup path. `patchguard rollback-patch APPLICATION_ID` restores the backup
only if the target still has the recorded applied hash and the backup still has the recorded source
hash. Any intervening target edit causes rollback to stop without overwriting it.

## Acceptance criteria

- Application is CLI-only and requires exact patch-ID confirmation.
- Only verified patches with a recorded review workspace can be promoted.
- The registered checkout itself is never an allowed target.
- The target must be an authorized linked Git worktree; no Git commands or hooks are executed.
- Only the stored, safe relative patch path can be changed, after source-hash revalidation.
- A private backup exists before the atomic write and is retained after success or failure.
- Rollback is hash-guarded and restores only the single patched file.
- Application state is persisted for audit and recovery.
