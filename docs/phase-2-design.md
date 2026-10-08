# Phase 2 repository intelligence

## Architecture

Phase 2 adds a read-only indexing service between repository authorization and persistence:

```text
authorized repository
  -> safe file discovery
  -> language-adapter selection
  -> Python AST adapter
  -> normalized index snapshot
  -> symbols / imports / calls / parse issues
```

An index is an immutable observation tied to a repository and its known commit. Re-indexing creates
a new snapshot rather than silently changing historical results. API and CLI queries default to the
latest completed snapshot.

The Python adapter uses the standard library AST without importing modules. Call resolution is
deliberately conservative: exact local qualified names and unambiguous symbol names may be linked;
otherwise the original call expression is retained with no claimed target. Function summaries count
branches, loops, returns, raises, and awaits but do not claim complete control-flow analysis.

## Security boundaries

- Every index request re-authorizes the stored canonical repository path.
- Files must resolve beneath both the repository and an authorized root.
- Symlinked source files and directories cannot escape the repository.
- File size and file-count limits bound parsing work.
- Source is decoded using declared Python encodings; decoding and syntax failures become data.
- Comments, docstrings, names, strings, and configuration text are untrusted repository data.
- The index contains locations and structural metadata, not source bodies or secret values.
- No repository command, import, hook, build, test, package installation, or network call occurs.

## Acceptance criteria

- Detect common Python source roots, CI workflows, container, build, config, and infrastructure files.
- Safely parse functions, async functions, classes, methods, imports, and call sites.
- Persist immutable index snapshots with explicit completed/partial/failed status.
- Preserve repository-relative paths and report malformed/unsupported files without false success.
- Expose profile, index summary, symbols, imports, calls, and parse issues through API and CLI.
- Provide source/sink and taint-flow contracts without claiming whole-program taint analysis.
- Cover malformed syntax, declared encodings, oversized files, symlink escapes, prompt-injection text,
  ambiguous calls, worktree Git metadata, API retrieval, migrations, and non-mutation in tests.
- Pass formatting, linting, strict typing, all tests, live demo indexing, and hash verification.

