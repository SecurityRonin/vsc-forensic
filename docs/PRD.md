# vsc-forensic — Purpose & Scope

> **Tier: library.** `vsc-forensic` ships no binary an examiner runs — it is a
> two-crate Rust library (a reader + an analyzer) that other tools link. Per the
> fleet PRD & ADR standard, a library carries this lighter *Purpose & Scope* in
> the unified `docs/PRD.md` filename, not a full product-requirements document.
> The load-bearing design decisions are recorded as ADRs under
> [`docs/decisions/`](decisions/).

## What it is

`vsc-forensic` is the Windows **Volume Shadow Copy (VSS)** member of the
SecurityRonin forensic fleet — the `[P^H]` disk-history layer. Windows keeps
point-in-time snapshots of an NTFS volume under `System Volume Information`: each
shadow copy preserves the blocks that were about to change, so the live volume
plus the VSS stores together encode a temporal cohort of the filesystem's past
states.

The repo ships two crates (see [ADR 0001](decisions/0001-reader-analyzer-two-crate-split.md)):

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `vsc-core` (lib `vsc`) | reader / decoder | `uuid`, `thiserror` | typed VSS catalog / store / block records; reconstructed snapshot blocks |
| `vsc-forensic` | anomaly analyzer | `vsc-core`, `forensicnomicon`, `jiff` | graded `forensicnomicon::report::Finding`s |

## Who links it

- **`vsc-core`** — any Rust tool that needs to enumerate VSS shadow copies, read
  store metadata, or reconstruct a snapshot's copy-on-write view of a volume. It
  takes any `Read + Seek` positioned at the NTFS volume, so it is container- and
  filesystem-agnostic.
- **`vsc-forensic`** — the fleet ORCHESTRATION layer (issen, disk4n6) and any
  analyzer pipeline that aggregates `forensicnomicon::report` findings. It turns
  the stores `vsc-core` decodes into graded, uniform findings that sit beside
  every other artifact analyzer in one `Report`.

Neither crate is run directly by an examiner; the runnable surface is the fleet
CLI/GUI that links them.

## What it does

- Locates the VSS volume header (offset `0x1E00`) and walks the **catalog** of
  shadow-copy stores — store GUID, size, sequence, creation FILETIME.
- Decodes each store's **metadata** — shadow-copy IDs, attribute flags,
  originating machine.
- **Reconstructs** a snapshot as a point-in-time view of the volume: overlays the
  store's copy-on-write blocks on the live volume so any 16 KiB block can be read
  back as it was at snapshot time
  ([ADR 0006](decisions/0006-cow-snapshot-reconstruction.md)).
- Grades shadow-copy timeline / integrity **anomalies** as `VSC-*` findings
  ([ADR 0008](decisions/0008-findings-as-graded-observations.md)):
  `VSC-NO-SHADOW-COPIES`, `VSC-STORE-PRESENT`, `VSC-SEQUENCE-GAP`,
  `VSC-STORE-NON-PERSISTENT`.

## Scope

- Read-only decoding of the VSS on-disk store/catalog/block structures from an
  NTFS volume image ([ADR 0004](decisions/0004-vss-on-disk-format-decoding.md)).
- Copy-on-write snapshot reconstruction (read any block as it was at snapshot
  time).
- Severity-graded anomaly findings in the shared fleet report vocabulary.
- Panic-free, `forbid(unsafe)`, fuzzed parsing of untrusted images
  ([ADR 0003](decisions/0003-forbid-unsafe-panic-free-readers.md)).

## Non-goals

- **No image-container or filesystem decoding.** The crate takes a positioned
  `Read + Seek` over the NTFS volume; opening E01/VMDK/raw containers or walking
  NTFS is the job of the fleet container/filesystem layers (the Tier-1 tests use
  `ewf` only as a dev-dependency to feed a real image — [ADR 0007](decisions/0007-tier1-validation-against-libvshadow.md)).
- **No user-facing CLI/GUI/MCP server.** This is a linked library; the runnable
  surface belongs to issen / disk4n6.
- **No verdicts.** Findings are observations framed "consistent with," never a
  determination of deletion or any legal conclusion — the analyst or tribunal
  concludes ([ADR 0008](decisions/0008-findings-as-graded-observations.md)).
- **No forwarder-descriptor reconstruction path** is exercised — none occurred in
  the validation corpus; the case is a documented, honest limit
  ([ADR 0006](decisions/0006-cow-snapshot-reconstruction.md)), not silently
  assumed handled.

## Validation approach

Correctness is proven against an **independent third-party oracle** — libvshadow
via `pyvshadow` — run on the real public Magnet PC-MUS-001.E01 image
([ADR 0007](decisions/0007-tier1-validation-against-libvshadow.md)). Catalog and
store-metadata output matches the oracle field-for-field, and reconstruction
reproduces the snapshot's bytes block-for-block across all four paths
(passthrough / zero-fill / plain COW / overlay), validated over 1,415 blocks
(`docs/RECONSTRUCTION.md`). Every parsed structure has a `cargo-fuzz` target whose
invariant is "must not panic," and CI gates 100% line coverage. Format research
behind the design is in [`docs/RESEARCH.md`](RESEARCH.md).
