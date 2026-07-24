# 2. Crate naming: `vsc-core` package with `[lib] name = "vsc"`

Date: 2026-07-24
Status: Accepted

## Context

The repo is `vsc-forensic` — a single-format repo, so the fleet naming grammar
(Pattern A) fixes the two crate *package* names as `vsc-core` (reader) and
`vsc-forensic` (analyzer). Two questions remain: what the reader's *import path*
should be, and why the reader is not simply published as the bare `vsc` package.

The naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar" and
"Crate-structure standard") says: publish the reader as `<x>-core` so its name is
self-describing on crates.io (read bare, `vsc-core` says "the core of the
`vsc-forensic` suite"), and give it `[lib] name = "<x>"` so consumers write the
terse `use <x>::…` rather than `use <x>_core::…` — provided the bare import name
does not hijack a popular third-party crate's namespace (the reason `ntfs-core`
keeps `ntfs_core` instead of `ntfs`). `vsc` is not a popular third-party import,
so the terse form is safe here.

## Decision

1. **Reader package = `vsc-core`** (`core/Cargo.toml` `name = "vsc-core"`).
2. **Reader import path = `vsc`** via `[lib] name = "vsc"` (`core/Cargo.toml`),
   so both the README examples and `vsc-forensic` write `use vsc::VssVolume`.
3. **Analyzer package = `vsc-forensic`**, imported as `vsc_forensic`.
4. The `vsc-core → vsc` mapping is wired once in the workspace dependency table:
   `vsc = { version = "0.2", path = "core", package = "vsc-core" }`
   (root `Cargo.toml` `[workspace.dependencies]`), so members depend on `vsc`
   while the published artifact is `vsc-core`.

## Consequences

- On crates.io the two artifacts read as a matched pair (`vsc-core` +
  `vsc-forensic`), self-describing without repo context.
- Consumer code stays terse (`use vsc::…`) while the published name stays
  self-describing — the standard's stated best of both.
- The workspace uses a `path` dep during development; per the fleet
  "prefer the published registry crate over a `path` dependency" rule, dependents
  switch to the registry `version` once `vsc-core` is published (the dep entry
  already carries `version = "0.2"` for exactly this).
- Renames are settled before the crates.io 72-hour deletion window closes; the
  names above are the committed final form.
