# Phase 6 — review-only patch planning

Phase 6 turns a persisted security finding into a structured plan for human review. The planner
uses the finding location and evidence already stored by PatchGuard, plus the latest evidence-bound
assessment when one exists. It does not inspect source files, call a model, generate a diff, change
finding status, or write to the target repository.

Each plan records the proposed file list, strategy, expected behavioral change, compatibility
risks, required regression coverage, rollback guidance, and a SHA-256 digest of its input context.
The only proposed file is the finding's persisted repository-relative path. Plans are immutable
records; requesting another plan creates a new record so a later assessment can inform it.

Plans are created with `POST /findings/{finding_id}/patch-plans` or
`patchguard plan-patch FINDING_ID`, retrieved as part of `GET /findings/{finding_id}`, and stored in
`security_patch_plans`.

## Acceptance criteria

- Planning is based only on persisted finding and assessment data.
- The proposed file path always comes from the finding's normalized location.
- Plans identify behavior, compatibility risks, regression tests, and rollback guidance.
- A context digest makes the plan's source evidence traceable.
- Unknown findings return not found; repeated planning preserves prior plans.
- API and CLI expose plans without changing repository files, patches, or finding status.
- No repository code, build, test, or package command runs during planning.

Patch generation, application, and verification remain separate later phases and require their own
review and execution boundaries.
