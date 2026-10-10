# Phase 9 — isolated patch review workspaces

Phase 9 materializes a successfully verified patch into a separate PatchGuard-owned workspace.
The workspace is copied from the authorized repository with Git metadata, symlinks, virtual
environments, and likely secret files/content excluded. The source file hash is checked again
before the diff is applied to the copy. Workspace creation is bounded by the configured file and
byte limits and is atomic within the configured workspace root.

Set `PATCHGUARD_PATCH_WORKSPACE_ROOT` to a private directory outside the registered repository. Create a
workspace with `POST /patches/{patch_id}/workspaces` or `patchguard patch-workspace PATCH_ID`.
Retrieve workspace metadata using `GET /patch-workspaces/{workspace_id}`. The API and CLI return the
workspace path for human review.

Workspace creation requires a patch with `VERIFIED` status and an unchanged source hash. The
registered repository is never modified. The workspace is a review artifact; accepting or merging
it back into the repository remains a separate, explicitly authorized action.

## Acceptance criteria

- Only verified patches can be materialized.
- Patch source hash is rechecked immediately before copying.
- The configured workspace root cannot be inside the registered repository.
- Snapshot file count and total bytes are bounded; Git metadata, symlinks, and likely secrets are
  excluded.
- The diff is applied only to a staged temporary copy, then atomically moved to a unique workspace.
- Repeated requests return the existing workspace instead of creating duplicate copies.
- No Git command, hook, repository test, or target-repository write occurs.
