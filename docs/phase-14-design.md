# Phase 14 — JavaScript/TypeScript foundation

Phase 14 extends repository intelligence and static inventory to JavaScript and TypeScript without
executing repository code. The adapter recognizes common declaration, import, and call spellings
within configured file-size and repository-file limits. It is intentionally heuristic: it is not a
JavaScript parser, does not provide full syntax validation, and its call/symbol metadata is not a
security proof.

The source scanner reports explicit `eval(...)` and `new Function(...)` constructs for review. It
does not attempt broad framework-specific taint analysis. Package inventory reads only root
`package.json`, including production, development, optional, and peer dependency groups. Exact
three-part semantic versions are marked pinned; tags, ranges, URLs, and workspace references are
not. No npm/yarn/pnpm command, network request, or package installation occurs.

The local advisory matcher remains Python-only: npm version semantics and advisory sources require
a separately reviewed design before matching is enabled. Lockfile graph resolution, full AST
parsing, framework rules, and further languages remain future work.
