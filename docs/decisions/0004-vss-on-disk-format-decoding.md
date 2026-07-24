# 4. VSS on-disk format decoding — offsets, block size, endianness, GUID layout

Date: 2026-07-24
Status: Accepted

## Context

VSS has no public Microsoft on-disk specification. The community reference is
libyal's **libvshadow** and its documentation; `vsc-core` must decode the same
structures the same way to be cross-checkable against it. The format research
behind these choices is written up in `docs/RESEARCH.md`, and the reconstruction
layout in `docs/RECONSTRUCTION.md`. Getting a single offset, block size, or the
GUID byte order wrong ships green tests while decoding garbage — these constants
are load-bearing and must match the reverse-engineered reference exactly.

## Decision

Decode the VSS structures per the libvshadow-settled layout, encoding the
constants directly in the reader:

1. **VSS volume header at byte offset `0x1E00`** within the NTFS volume
   (`catalog::VSS_VOLUME_HEADER_OFFSET = 0x1E00`); offset 0 of the input is the
   NTFS boot sector (`core/src/lib.rs` doc header).
2. **16 KiB block size** for both catalog and store blocks
   (`catalog::BLOCK_SIZE = 16_384`); catalog block header and each entry are
   128 bytes (`CATALOG_BLOCK_HEADER_LEN` / `CATALOG_ENTRY_LEN`).
3. **Record-type discrimination:** volume header `0x01`, catalog block `0x02`,
   store header block `0x0004`, block-descriptor list `0x0003`, ranges `0x0005`,
   bitmap `0x0006` (`catalog.rs` / `store.rs` / `block.rs` constants).
4. **All multi-byte fields little-endian** (`core/src/bytes.rs`), per the
   Windows on-disk convention.
5. **The VSS identifier GUID `3808876b-c176-4e48-b7ae-04046e6cc752`** stored in
   mixed-endian layout (first three fields LE, last eight BE) is kept as a raw
   16-byte constant `VSS_IDENTIFIER` (`core/src/guid.rs`) and matched at offset 0
   of the volume header, every catalog block header, and every store block.
6. **Store metadata reached via the catalog type-0x03 entry** (store header at
   entry `+32`, bitmap pointer at entry `+48`); the block-descriptor list is the
   block immediately after the store header (`store_header_offset + 16384`) and
   chains via `next_offset` (`docs/RECONSTRUCTION.md` table; `catalog.rs`).

Store attribute flags (`store::AttributeFlags`: PERSISTENT `0x1`, CLIENT_ACCESSIBLE
`0x4`, DIFFERENTIAL `0x20000`, …) and block-descriptor flags (`block.rs`:
FORWARDER `0x01`, OVERLAY `0x02`, NOT_USED `0x04`) are likewise fixed to the
documented values.

## Consequences

- `vsc-core` output is field-for-field comparable to `pyvshadow`/libvshadow on a
  real image (store count, GUID, volume size, creation FILETIME, shadow-copy IDs
  — see ADR 0007), which is the whole basis of the correctness claim.
- The constants are named and documented, not magic literals scattered in the
  parse code, so a future format revision is a localized edit.
- A Windows 2003 R2 catalog that lacks the type-0x03 pointer is handled by a
  typed `VssError::StoreInfoUnavailable` rather than a wrong decode
  (`core/src/error.rs`) — the format's real discontinuity is surfaced, not
  papered over.
- FILETIME is decoded but rendered upward; calendar conversion is delegated (ADR
  0005) rather than reimplemented in the reader.
