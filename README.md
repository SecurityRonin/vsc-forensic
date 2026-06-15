# vsc-forensic

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Windows Volume Shadow Copy (VSS) forensics for Rust — a panic-free reader for the shadow-copy store/catalog structures, and a graded anomaly analyzer that turns each NTFS snapshot into evidence you can diff across time.**

**Status:** early-stage scaffold — format research complete (see [docs/RESEARCH.md](docs/RESEARCH.md)), parser under construction.

VSS is how Windows keeps point-in-time snapshots of an NTFS volume under `System Volume Information`: each shadow copy preserves the blocks that were about to change, so the live volume plus the VSS stores together encode the temporal cohort of the filesystem's past states. `vsc-forensic` is the planned `[P^H]` disk-history member of the forensic fleet — it will navigate that VSS region by snapshot, enumerate the catalog of stores and their block lists, and surface shadow-copy timeline and integrity anomalies as fleet findings.

## The two-crate split

Following the fleet reader/analyzer standard, the workspace will ship two crates:

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `vsc-core` | reader / decoder | `thiserror` | typed VSS catalog / store / block records |
| `vsc-forensic` | anomaly analyzer | `vsc-core`, `forensicnomicon` | graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s |

The reader stays pure — it decodes bytes and makes no judgments. All *forensic meaning* lives in the analyzer, a side-effect-free function of already-decoded records. That separation is why `vsc-core` will be useful on its own and why `vsc-forensic` drops straight into a fleet `Report` next to every other analyzer.

Both crates are doc-only stubs today; no public API is exported yet.

## Roadmap

| Stage | Status |
|---|---|
| Format research (VSS catalog/store/block layout) | ✅ complete — [docs/RESEARCH.md](docs/RESEARCH.md) |
| `vsc-core` — VSS volume header + catalog enumeration | planned |
| `vsc-core` — store + block-list decode, snapshot view | planned |
| `vsc-forensic` — anomaly auditor (`VSC-*` findings) | planned |
| Fuzz targets + real-VSS-image validation (vs `libvshadow`) | planned |

## Built to the fleet bar

Even as a scaffold, the workspace already enforces the fleet's hardening contract: `#![forbid(unsafe_code)]` across both crates, the Paranoid-Gatekeeper clippy set (`unwrap_used`/`expect_used` denied, pedantic warnings), `cargo-deny` supply-chain gating, and a 100%-line-coverage CI gate. As the parser lands it will be bounds-checked, fuzzed, and validated against real VSS images with an independent oracle.

## Documentation

The curated docs site is built with MkDocs and served from GitHub Pages. See [docs/RESEARCH.md](docs/RESEARCH.md) for the VSS format research that guides the design.

[Privacy Policy](https://securityronin.github.io/vsc-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vsc-forensic/terms/) · © 2026 Security Ronin Ltd
