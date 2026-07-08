# vsc-forensic test data & Tier-1 validation

This repo parses Windows **Volume Shadow Copy (VSS)** stores. Correctness is
proven against an **independent third-party oracle** — libvshadow
(`pyvshadow`), the libyal reference implementation — run on a **real public CTF
disk image**, not on fixtures we authored. See `../oracle/vshadow_oracle.py`
for the reproducible ground-truth harness and the fleet catalog
(`issen/docs/corpus-catalog.md`) for the index.

## Tier-1 oracle image (env-gated, NOT committed)

The oracle image is large and gitignored; the integration test skips cleanly
when it is absent (set `VSC_ORACLE_IMAGE` to run it).

#### PC-MUS-001.E01 — Magnet Virtual Summit 2023 CTF (Windows 11, GPT)

- **Source:** Magnet Forensics — Magnet Virtual Summit 2023 CTF ("Boombox" / PC-MUS-001).
  Writeups: <https://www.magnetforensics.com/blog/magnet-virtual-summit-2023-ctf/>
- **Path in fleet:** `issen/tests/data/magnet-summit-2023-ctf/PC-MUS-001.E01`
- **Media size:** 238 GiB (GPT); main NTFS volume = part 6 at **byte offset 122683392**.
- **Ground truth (from `pyvshadow` 20240504, confirmed 2026-07-08):** exactly **1 VSS store**
  on the main NTFS volume:

  | field | value |
  |---|---|
  | store identifier | `1afc8871-8c76-11ed-8c4d-f894c2dfe804` |
  | creation time (UTC) | `2023-01-04 21:38:00.8254268` — raw FILETIME `133173418808254268` |
  | shadow volume size | `255136931328` |

  Note: `pyvshadow` prints the creation time truncated to microseconds
  (`.825426`); the raw on-disk FILETIME is `133173418808254268` (100 ns units),
  which is the exact value `vsc-core` reads and `oracle_pcmus001.rs` asserts.

  Reproduce: `python3 ../oracle/vshadow_oracle.py <path>/PC-MUS-001.E01`

- **Redistribution:** Magnet CTF images are distributed for training; not
  redistributed here (gitignored, downloaded manually). Provenance only.

## Images checked that carry NO VSS (documented negatives)

Enumerated with the same oracle harness (Doer-Checker — do not re-guess these):

- `dfirmadness-szechuan-sauce/E01-DC01/…CDrive.E01` — NTFS C: volume, VSS volume
  header at `0x1E00` is all-zero → **0 stores**.
- `defcon-dfir-ctf-2018/MaxPowersCDrive.E01` — single 50 GiB NTFS, `0x1E00`
  all-zero → **0 stores**.

## Phase-2 reconstruction oracle

`../oracle/reconstruction_oracle.json` holds the pyvshadow-derived sha256 of the
16384-byte block that libvshadow reconstructs for store 0 of PC-MUS-001.E01 at
representative volume offsets — passthrough (`0`, `16384`), zero-fill (`163840`),
plain-COW (`3997696`), and overlay (`4227072`). `vsc-core`'s `SnapshotReader` must
reproduce each block byte-for-byte. The full copy-on-write algorithm (validated
byte-for-byte over 1,415 blocks against pyvshadow) is documented in
[`docs/RECONSTRUCTION.md`](../../docs/RECONSTRUCTION.md).

## Synthetic unit fixtures

Fast TDD fixtures for parser mechanics (VSS volume header @0x1E00, catalog block,
catalog entry type 0x02, store block header/info, block descriptors) are built
in-code by test helpers — Tier-3, backstopped by the Tier-1 env-gated test
above.

#### `build_image(with_type3: bool)` — minimal valid VSS volume image

- **Generator:** `core/src/tests.rs` — `fn build_image` (with `fn wr` / `fn utf16le`
  byte-writer helpers alongside it). Produces a `Vec<u8>` with a VSS volume header
  at `0x1E00`, one catalog block at `0x4000` holding a type-0x02 snapshot entry
  (+ optional type-0x03 store pointer), and a store block header + store
  information at `0x8000`, carrying KNOWN store/shadow-copy GUIDs, volume size,
  sequence, flags, FILETIME, attribute flags, and UTF-16LE machine strings.
- **Consumed by:** the `#[cfg(test)] mod tests` unit suite in `core/src/tests.rs`.
- **Tier-3:** fixture and expected answer both authored here; it proves parser
  mechanics only. The authoritative check is the Tier-1 oracle test above.
