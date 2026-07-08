# vsc-forensic

Windows Volume Shadow Copy (VSS) forensics for Rust — the `[P^H]`
disk-history member of the forensic fleet.

!!! success "Status"
    Shipping. `vsc-core` and `vsc-forensic` are published on crates.io.
    VSS catalog + store-metadata enumeration, the anomaly auditor, and copy-on-write
    snapshot reconstruction are complete and Tier-1 validated against `libvshadow`.
    Format research: [Format Research](RESEARCH.md); reconstruction algorithm:
    [Reconstruction](RECONSTRUCTION.md).

## What it does

Windows creates **Volume Shadow Copies** — point-in-time snapshots of an NTFS
volume — under `System Volume Information`. Each shadow copy preserves the blocks
that were about to be overwritten, so the live volume plus the VSS stores together
encode a temporal cohort of the filesystem's past states.

`vsc-forensic`:

- locates the VSS volume header and walks the **catalog** of shadow-copy stores,
- enumerates each store's descriptor (GUID, size, sequence, creation time) and
  per-snapshot **metadata** (shadow-copy IDs, attribute flags, originating machine),
- grades shadow-copy timeline and integrity **anomalies** as
  `forensicnomicon::report` findings that aggregate with every other artifact
  layer, and
- **reconstructs** each snapshot as a point-in-time view of the volume — copy-on-write
  blocks overlaid on the live volume — so any block can be read back as it was at
  snapshot time.

## The two-crate split

Following the fleet reader/analyzer standard:

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `vsc-core` | reader / decoder | `uuid`, `thiserror` | typed VSS catalog/store records |
| `vsc-forensic` | anomaly analyzer | `vsc-core`, `forensicnomicon` | graded `Finding`s |

The reader stays pure — it decodes bytes and makes no judgments. All *forensic
meaning* lives in the analyzer, a side-effect-free function of already-decoded
records. That separation is why `vsc-core` is useful on its own and why
`vsc-forensic` drops straight into a fleet `Report`.

## Capabilities

| Capability | Status |
|---|---|
| Format research (VSS catalog/store/block layout) | ✅ complete — see [Format Research](RESEARCH.md) |
| `vsc-core` — VSS volume header + catalog enumeration | ✅ |
| `vsc-core` — store metadata decode (shadow-copy IDs, attribute flags, machine) | ✅ |
| `vsc-forensic` — anomaly auditor (`VSC-*` findings) | ✅ |
| `vsc-core` — COW snapshot reconstruction (`snapshot().read_block/read_at`) | ✅ |
| Fuzz targets + Tier-1 real-VSS-image validation (vs `libvshadow`) | ✅ |

[Privacy Policy](https://securityronin.github.io/vsc-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/vsc-forensic/terms/) · © 2026 Security Ronin Ltd
