# 6. Copy-on-write snapshot reconstruction (Phase 2)

Date: 2026-07-24
Status: Accepted

## Context

Enumerating shadow-copy stores (Phase 1) tells an analyst *that* snapshots exist
and their metadata, but not *what the volume looked like* at snapshot time. The
forensic value of VSS is the ability to read a file, MFT record, or block as it
was in the past. That requires reconstructing a snapshot's copy-on-write view:
overlaying the blocks the store preserved on top of the live volume.

The initial release deliberately shipped only Phase 1. `core/src/block.rs`
records the staging: it parses the diff-area records "so a consumer sees the
copy-on-write mapping structurally," while "the full snapshot-reconstruction
engine … is Phase 2 and is deliberately **not** implemented here." The git
history shows the follow-through: the reconstruction engine landed in `0.2.0`
(`ad1d1ba` RED tests, `6f6a2a2` GREEN engine, `d4b61fe`/`7647bc7` capturing the
store bitmap offset from catalog type-0x03, `41aa79b` release).

The risk in a reconstruction algorithm is the "LZNT1 trap" — a self-consistent
round-trip that passes while the algorithm is wrong. So the algorithm had to be
pinned to an independent oracle, not just to synthetic fixtures.

## Decision

1. **Implement COW reconstruction in `core/src/reconstruct.rs`**, exposed as
   `VssVolume::snapshot(index) → Snapshot`, then `Snapshot::read_block(offset)` /
   `Snapshot::read_at(offset, buf)`.
2. **The algorithm is specified in `docs/RECONSTRUCTION.md`** and encoded exactly.
   For a 16384-byte block at volume offset `off` (`bn = off / 16384`,
   `base = bn * 16384`), collect descriptors whose `original_offset == base`:
   - **descriptor set non-empty** → base = last *plain* descriptor's store block
     (flags `& 0x07 == 0`), else the live volume block; then each *overlay*
     descriptor (0x02 set, 0x04 clear) replaces the 512-byte sub-blocks its
     `allocation_bitmap` selects;
   - **descriptor set empty, bitmap bit set** → 16384 zero bytes (unallocated);
   - **descriptor set empty, bitmap bit clear** → live passthrough.
3. **Every offset is range-checked against the volume before seeking** — a
   corrupt descriptor reconstructs as zeros / is skipped, never panics or reads
   out of bounds (`reconstruct.rs` doc header; consistent with ADR 0003).
4. **Forwarder (0x01) resolution is documented as an unencountered edge**, not
   silently assumed away — none occurred in the validation corpus, and the code
   comment says so rather than pretending the case is handled.

## Consequences

- An analyst can materialize any block of a snapshot and read past filesystem
  state — the core forensic capability of the `[P^H]` disk-history layer.
- The algorithm is validated byte-for-byte against libvshadow over 1,415 blocks
  spanning all four paths — 489 passthrough, 818 zero-fill, 28 plain-COW, 80
  overlay — 100% match (`docs/RECONSTRUCTION.md`; ADR 0007). This retires the
  LZNT1-trap risk with a Tier-1 oracle.
- `core/src/block.rs`'s "Phase 2 … deliberately not implemented" comment is now
  historical staging language that the shipped `reconstruct.rs` supersedes.
- Forwarder-descriptor volumes are a known, documented gap should one ever
  appear; the honest limit is recorded rather than hidden.
