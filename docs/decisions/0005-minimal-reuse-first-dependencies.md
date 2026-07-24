# 5. Minimal, reuse-first dependencies — don't reinvent solved primitives

Date: 2026-07-24
Status: Accepted

## Context

Two temptations exist when parsing a binary format: hand-roll every helper to
keep the dependency tree at zero, or pull a heavy framework. The fleet position
is neither — reuse *mature, audited* crates for solved primitives (calendar math,
GUID formatting, error boilerplate) and keep the tree otherwise minimal so the
reader stays a lean, low-MSRV library others can link. Two solved primitives
appear here: rendering a mixed-endian Windows GUID to canonical string, and
converting a FILETIME to a human-readable RFC 3339 timestamp.

The GUID case is called out in the code itself: `core/src/guid.rs` notes that
`dpapi-forensic` and `winevt-binxml` each hand-roll a mixed-endian GUID formatter
separately — "a fleet cleanup opportunity" — and deliberately does *not* add a
third copy.

## Decision

1. **Reader (`vsc-core`) dependencies are exactly `uuid` + `thiserror`**
   (`core/Cargo.toml`):
   - `uuid` for GUID rendering — `format_guid` delegates to
     `uuid::Uuid::from_bytes_le`, whose LE-first-three-fields layout *is* the
     on-disk Windows GUID encoding, so the output matches libvshadow's rendering
     (`core/src/guid.rs`). No hand-rolled mixed-endian formatter.
   - `thiserror` for the `VssError` enum (`core/src/error.rs`) — standard
     ergonomic error derivation, not a bespoke `impl Error`.
2. **Timestamp rendering lives in the analyzer, via `jiff`.** The workspace dep
   comment states the intent: "REUSE, don't reinvent calendar math: jiff renders
   FILETIME as RFC 3339" (root `Cargo.toml`). `jiff` is a `vsc-forensic`
   dependency only (`forensic/Cargo.toml`) — the reader stays free of calendar
   math and keeps FILETIME as a raw `u64`; the analyzer applies the
   `FILETIME_EPOCH_DIFF` offset and renders (`forensic/src/lib.rs`).
3. **No zero-dep purity for its own sake, no framework.** The bounds-checked
   byte readers (`bytes.rs`) are kept in-crate because they are trivial and
   central to the panic-free contract (ADR 0003); everything with an audited
   ecosystem answer is reused.

## Consequences

- `vsc-core` has a two-crate dependency surface (`uuid`, `thiserror`), keeping it
  cheap to link and easy to hold at a low MSRV (ADR 0009).
- GUID and timestamp rendering match the independent oracle by construction
  (ADR 0007), because both delegate to the same well-known encodings libvshadow
  uses.
- The reader carries no calendar dependency; a consumer that only wants raw VSS
  structures does not pull `jiff`.
- A future fleet consolidation of the duplicated mixed-endian GUID formatters
  (dpapi-forensic / winevt-binxml) would not touch this crate — it already reuses
  `uuid`.
