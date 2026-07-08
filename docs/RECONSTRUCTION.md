# VSS snapshot reconstruction — validated algorithm (Phase 2)

The copy-on-write reconstruction algorithm below was **empirically validated
byte-for-byte against libvshadow** (`pyvshadow` 20240504) over 1,415 blocks of
store 0 of the Magnet PC-MUS-001.E01 image (489 passthrough, 818 zero-fill, 28
plain-COW, 80 overlay) — 100% match. This is the authoritative spec for
`vsc-core`'s `SnapshotReader`.

## Store metadata layout (per store)

Reachable from the catalog type-0x03 entry (see `catalog.rs`):

| Structure | Location | Record type | Chain |
|---|---|---|---|
| Store header + store info | catalog entry **+32** | 0x0004 | single block |
| **Block-descriptor list (diff area)** | **store_header_offset + 16384** | 0x0003 | follow `next_offset` (@40) |
| Store block ranges | catalog entry **+40** | 0x0005 | follow `next_offset` |
| **Store bitmap** | catalog entry **+48** | 0x0006 | follow `next_offset` (@40) |

The block-descriptor list is *not* pointed at by the catalog entry; it is the
block immediately after the 0x04 store header (`store_header_offset + BLOCK_SIZE`),
and chains via `next_offset` like every other store-block chain.

## Block descriptor (32 bytes, after the 128-byte 0x0003 block header)

`original_offset` @0 · `relative_store_offset` @8 · `store_offset` @16 ·
`flags` @24 · `allocation_bitmap` @28 (all little-endian). Flags: `0x01` forwarder,
`0x02` overlay, `0x04` not-used. A zeroed 32-byte record terminates the block.

## Store bitmap (0x0006)

Concatenate each 0x0006 block's payload (bytes after the 128-byte header) in
`relative_offset` order. Bit *b* (LSB-first within each byte) corresponds to
volume block *b* (block = `volume_offset / 16384`). **bit set (1) ⇒ the block was
unallocated in the snapshot ⇒ reads as zeros.**

## Reconstruction of one 16384-byte block at volume offset `off`

Let `bn = off / 16384`, `base = bn * 16384`. Collect all descriptors whose
`original_offset == base` (the "descriptor set" for this block).

1. **Descriptor set is non-empty:**
   - `plains` = descriptors with none of forwarder/overlay/not-used set (flags & 0x07 == 0).
   - `overlays` = descriptors with overlay (0x02) set and not-used (0x04) clear.
   - **Base data** = the last plain descriptor's store block (`read 16384 @ store_offset`)
     if any plain exists; **otherwise the live volume block** (`read 16384 @ base`).
   - For each overlay descriptor, split its store block into 32 sub-blocks of
     `16384/32 = 512` bytes; for each bit *i* set in `allocation_bitmap`, replace
     `out[i*512 .. (i+1)*512]` with the overlay's sub-block *i*.
   - (Forwarder (0x01) and not-used (0x04) descriptors contribute no data here;
     forwarder resolution is a documented edge — none occurred in the corpus.)
2. **Descriptor set empty, bitmap bit == 1:** return 16384 zero bytes.
3. **Descriptor set empty, bitmap bit == 0:** passthrough — return the live volume block.

Reads spanning block boundaries are the per-block result concatenated and sliced.
Every `store_offset` / bitmap offset is range-checked against the volume before
seeking (a corrupt descriptor must never panic or read out of bounds).

## Tier-1 oracle

`tests/oracle/reconstruction_oracle.json` holds the pyvshadow-derived sha256 of
the reconstructed block at representative offsets (passthrough / zero-fill /
plain-COW / overlay). `SnapshotReader` must reproduce each byte-for-byte. Re-derive
with `tests/oracle/vshadow_oracle.py` (extend for reconstructed reads via
`store.read_buffer_at_offset(16384, offset)`).
