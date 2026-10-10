# Phase 16 — npm lockfile inventory

Phase 16 adds offline inspection of npm `package-lock.json` formats 1, 2, and 3. It records exact
three-part package versions, including nested/transitive packages and scoped names, and associates
available npm dev/optional/peer metadata with dependency groups. npm advisory matching can use these
resolved versions as well as exact root `package.json` versions.

The parser reads a bounded file, caps inventory at 100,000 package entries, rejects unsupported
lockfile versions, and never invokes npm, executes scripts, resolves packages, or accesses the
network. Symlink escapes are rejected by the existing manifest boundary checks. Yarn and pnpm
lockfiles, integrity verification, workspace graph semantics, and package source URLs are not
interpreted. If both package.json and a lockfile are present, both are inventoried; findings retain
their respective evidence paths rather than silently merging the two records.
