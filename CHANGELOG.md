# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — initial scaffold

### Added

- Workspace scaffold for the planned `vsc-forensic` Volume Shadow Copy (VSS)
  crate — the `[P^H]` disk-history member of the forensic fleet.
  - Reader/analyzer split: `vsc-core` (raw VSS store/catalog reader) and
    `vsc-forensic` (anomaly auditor emitting `forensicnomicon::report` findings).
    Both are doc-only stubs pending the parser implementation.
  - Paranoid-Gatekeeper workspace lints (`unsafe_code = "forbid"`,
    `unwrap_used`/`expect_used = "deny"`, pedantic clippy), Apache-2.0 licence,
    and the fleet hygiene config (`deny.toml`, `.gitleaks.toml`, `clippy.toml`,
    `rustfmt.toml`, `renovate.json`, `.pre-commit-config.yaml`).
  - MkDocs documentation site and CI (`fmt`, `clippy`, `test`, MSRV, coverage,
    `cargo-deny`, docs) workflows.
  - VSS on-disk format research captured in [`docs/RESEARCH.md`](docs/RESEARCH.md)
    to guide the parser design.
