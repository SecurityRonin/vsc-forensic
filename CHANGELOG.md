# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-07-08

### Changed

- Documentation only: corrected the README, docs site, and crate metadata to
  reflect the shipped state (the 0.1.0 pages still described a "planned scaffold").
  `vsc-core` now carries a README on its crates.io page. No code changes.

## [0.1.0] — 2026-07-08

First release. `vsc-core` and `vsc-forensic` published to crates.io.

### Added

- **`vsc-core`** — panic-free reader for the Windows Volume Shadow Copy (VSS)
  on-disk structures, the `[P^H]` disk-history member of the forensic fleet.
  - `VssVolume::open` over any `Read + Seek` NTFS volume: reads the VSS volume
    header at `0x1E00`, walks the catalog of shadow-copy stores, and exposes each
    `StoreDescriptor` (store GUID, volume size, sequence, creation FILETIME).
  - `store_info` decodes a store's per-snapshot metadata — shadow-copy and
    shadow-copy-set GUIDs, attribute flags, originating/service machine strings.
  - Bounds-checked readers throughout (never panic, never read out of bounds,
    catalog-block iteration capped); GUIDs rendered via `uuid::from_bytes_le`.
- **`vsc-forensic`** — anomaly auditor over `vsc-core` emitting
  `forensicnomicon::report::Finding`s: `VSC-NO-SHADOW-COPIES` (consistent with
  MITRE T1490), `VSC-STORE-PRESENT`, `VSC-SEQUENCE-GAP`, `VSC-STORE-NON-PERSISTENT`.
- **Validation** — Tier-1 against `libvshadow` (via `pyvshadow`) on a real public
  CTF disk image: catalog and store-metadata output matches the oracle
  field-for-field (env-gated `oracle_pcmus001` test). `fuzz_catalog` /
  `fuzz_store` targets (invariant: must not panic) + `fuzz.yml`.
- Paranoid-Gatekeeper workspace lints (`unsafe_code = "forbid"`,
  `unwrap_used`/`expect_used = "deny"`, pedantic clippy), Apache-2.0 licence, the
  fleet hygiene config (`deny.toml`, `.gitleaks.toml`, `clippy.toml`,
  `rustfmt.toml`, `renovate.json`, `.pre-commit-config.yaml`), a MkDocs docs site,
  and CI (`fmt`, `clippy`, `test`, MSRV, 100%-line coverage, `cargo-deny`, docs,
  fuzz). VSS on-disk format research in [`docs/RESEARCH.md`](docs/RESEARCH.md).

### Planned

- Phase 2: COW block-list reconstruction — materialize each snapshot's
  point-in-time view of the volume for cross-snapshot state diffing.
