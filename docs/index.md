# vsc-forensic

Windows Volume Shadow Copy (VSS) forensics for Rust — the planned `[P^H]`
disk-history member of the forensic fleet.

!!! note "Status"
    Early-stage scaffold. The VSS on-disk format research is complete (see
    [Format Research](RESEARCH.md)); the parser is under construction. The crates
    below are doc-only stubs today.

## What it will do

Windows creates **Volume Shadow Copies** — point-in-time snapshots of an NTFS
volume — under `System Volume Information`. Each shadow copy preserves the blocks
that were about to be overwritten, so the live volume plus the VSS stores together
encode a temporal cohort of the filesystem's past states.

`vsc-forensic` will:

- locate the VSS volume header and walk the **catalog** of shadow-copy stores,
- enumerate each **store** and its **block list** mapping original volume blocks
  to their preserved copies,
- expose each snapshot as a point-in-time view so a consumer can **diff
  filesystem state across snapshots**, and
- grade shadow-copy timeline and integrity **anomalies** as
  `forensicnomicon::report` findings that aggregate with every other artifact
  layer.

## The two-crate split

Following the fleet reader/analyzer standard:

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `vsc-core` | reader / decoder | `thiserror` | typed VSS catalog/store/block records |
| `vsc-forensic` | anomaly analyzer | `vsc-core`, `forensicnomicon` | graded `Finding`s |

The reader stays pure — it decodes bytes and makes no judgments. All *forensic
meaning* lives in the analyzer, a side-effect-free function of already-decoded
records. That separation is why `vsc-core` will be useful on its own and why
`vsc-forensic` drops straight into a fleet `Report`.

## Roadmap

| Stage | Status |
|---|---|
| Format research (VSS catalog/store/block layout) | ✅ complete — see [Format Research](RESEARCH.md) |
| `vsc-core` — VSS volume header + catalog enumeration | planned |
| `vsc-core` — store + block-list decode, snapshot view | planned |
| `vsc-forensic` — anomaly auditor (`VSC-*` findings) | planned |
| Fuzz targets + real-VSS-image validation (vs `libvshadow`) | planned |

[Privacy Policy](https://securityronin.github.io/vsc-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vsc-forensic/terms/) · © 2026 Security Ronin Ltd
