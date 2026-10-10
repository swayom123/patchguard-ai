# Local advisory snapshot format

PatchGuard can match exact pinned Python or npm requirements against an operator-managed JSON snapshot.
It does not download, refresh, or trust a feed automatically. The operator is responsible for
reviewing the source, licensing, integrity, and update process of the snapshot.

Example:

```json
{
  "format_version": 1,
  "source": "organization-reviewed-osv-export",
  "generated_at": "2026-10-01T12:00:00Z",
  "advisories": [
    {
      "id": "CVE-2025-12345",
      "package": "urllib3",
      "affected": ">=1.0,<1.26.5",
      "fixed_version": "1.26.5",
      "severity": "HIGH",
      "summary": "A concise description of the affected dependency versions."
    }
  ]
}
```

Version 1 snapshots (as above) remain PyPI-only. Version 2 entries add an explicit `ecosystem`
field (`pypi` or `npm`); npm examples use npm semver ranges:

```json
{
  "format_version": 2,
  "source": "organization-reviewed-advisory-export",
  "generated_at": "2026-10-01T12:00:00Z",
  "advisories": [
    {
      "id": "GHSA-2345-2345-2345",
      "ecosystem": "npm",
      "package": "@example/library",
      "affected": ">=1.0.0 <1.4.2",
      "fixed_version": "1.4.2",
      "severity": "HIGH",
      "summary": "A concise description of affected npm package versions."
    }
  ]
}
```

`id` accepts CVE and GHSA identifiers. PyPI package names use Python distribution normalization;
npm package names are matched case-insensitively without converting dots to hyphens. The
`affected` field is a PEP 440 specifier set; `fixed_version` is informational and is not
independently validated as a package release. Severity is `LOW`,
`MEDIUM`, `HIGH`, or `CRITICAL` (the general enum also permits `INFO`). Summary is copied to
finding description and should not contain secrets or unrelated sensitive details. Duplicate IDs,
unknown fields, unsupported formats, timezone-free timestamps, and invalid specifiers fail the
advisory scanner.

Only exact `==` PyPI pins and exact `major.minor.patch` npm versions in root `package.json` are
eligible for matching. npm range matching supports comparator sets (`>=`, `>`, `<=`, `<`, `=`),
caret (`^`) and tilde (`~`) ranges. OR, wildcard, hyphen, tag, URL, and other unsupported forms
are rejected in the snapshot rather than guessed. npm advisories match only npm inventory and PyPI
advisories match only Python inventory. Advisory evidence records the ecosystem, feed source,
generation time, SHA-256 of the full snapshot, installed version, affected range, and suggested
fixed version. Snapshots older than
`PATCHGUARD_ADVISORY_MAX_AGE_DAYS` are reported as `SKIPPED`; malformed snapshots are `FAILED`.

The scanner reads at most 10 MB of advisory JSON and 5 MB per manifest. It performs no network
access and invokes no package manager. npm matching covers exact versions from root `package.json`
and npm `package-lock.json` versions 1–3, including transitive packages. Other lockfile formats are
not interpreted.
