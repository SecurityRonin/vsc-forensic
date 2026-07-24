# 3. `forbid(unsafe_code)` and Paranoid-Gatekeeper panic-free readers

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable** input: a VSS region read
out of a disk image whose every length, offset, and count is adversary-influenced.
A single out-of-bounds read, unchecked length, or `unwrap` on malformed input is
a denial-of-service (panic) or a memory-safety defect in a tool that runs against
hostile evidence. The fleet Security & Robustness standard ("Paranoid Gatekeeper")
is mandatory for every `*-core` / `*-forensic` crate.

Unlike the mmap-based readers in the fleet (`ewf`, `memory-forensic`) that
legitimately need one bounded `unsafe` for `memmap2::Mmap::map` and therefore
downgrade to `unsafe_code = "deny"` + a per-site allow, `vsc-core` reads through
an ordinary `Read + Seek` and never memory-maps. It has no justified need for any
`unsafe`, so the stronger, provable posture is available.

## Decision

1. **`#![forbid(unsafe_code)]`** in both crates (`core/src/lib.rs`,
   `forensic/src/lib.rs`) and `unsafe_code = "forbid"` in the workspace lints
   (root `Cargo.toml` `[workspace.lints.rust]`). `forbid` (not `deny`) is chosen
   because there is no unsafe site to exempt — a compiler-*proved* "no crafted
   input can corrupt memory," badge-able as `unsafe forbidden`.
2. **Panic-free by lint:** `unwrap_used` and `expect_used` are `deny`
   (`[workspace.lints.clippy]`), with `correctness`/`suspicious` denied and the
   `pedantic` group warned — the canonical fleet panic-free recipe.
3. **Bounds-checked readers as the single front door:** every multi-byte read
   goes through `core/src/bytes.rs` (`le_u16`/`le_u32`/`le_u64`/`read_guid`/
   `utf16le_string`), which return a zero value / empty string on an out-of-range
   offset instead of panicking. The `VssError` doc records the contract: "The
   reader never panics on malformed input" (`core/src/error.rs`).
4. **Bounded loops and sizes:** corrupt/looping chains are capped
   (`MAX_CATALOG_BLOCKS = 4096` in `catalog.rs`, `MAX_STORE_INFO_LEN = 1 << 20`
   in `store.rs`); reconstruction range-checks every store/bitmap offset against
   the volume before seeking (`core/src/reconstruct.rs` doc header).
5. **Fuzzing** covers every parsed structure (`fuzz_catalog`, `fuzz_store`,
   `fuzz_reconstruct`; commit `97b3aa8`, `4b7d680` added `fuzz.yml`), invariant
   "must not panic" — the runtime partner to the static lints.
6. Tests opt out of the panic lints only inside `#[cfg(test)]`
   (`#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` +
   `clippy.toml` `allow-unwrap-in-tests`), so tests may fail loudly.

## Consequences

- `vsc-core` and `vsc-forensic` earn the `unsafe forbidden` badge honestly (the
  README carries it) — a sharper trust signal than dependency hygiene for an
  evidence parser.
- Malformed VSS input degrades to safe defaults or a typed `VssError`, never a
  crash — verified empirically by the fuzz targets and statically by the lints.
- Adding an `unsafe` block anywhere becomes a hard compile error, so the posture
  cannot silently erode; `rg 'unsafe'` is expected to find nothing in production.
