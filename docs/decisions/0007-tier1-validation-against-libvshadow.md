# 7. Tier-1 validation against libvshadow on a real public image

Date: 2026-07-24
Status: Accepted

## Context

`vsc-core` reverse-engineers an undocumented format (ADR 0004) and reconstructs
snapshots with a non-trivial algorithm (ADR 0006). Synthetic fixtures we hand-encode
would validate only our own assumptions — the exact self-deception the fleet
Evidence-Based Rigor discipline warns against (tier-3, the LZNT1 trap). Correctness
of a parser/reconstructor that emits values must be pinned by an *independent*
oracle on *real* data (tier-1).

The DFIR ecosystem already has the settled reference: libyal's **libvshadow**
(via its `pyvshadow` binding). A real public artifact with VSS stores is
available in the Magnet **PC-MUS-001.E01** image. Reading that E01 requires an
image-container reader, and the fleet already publishes one (`ewf`).

## Decision

1. **Oracle = libvshadow / `pyvshadow`** (version `20240504`) — the independent
   third-party implementation, run on the same real image, as the ground-truth
   answer key. `tests/oracle/vshadow_oracle.py` derives the expected values.
2. **Real artifact = Magnet PC-MUS-001.E01**, a public CTF disk image. Catalog
   and store-metadata output is asserted field-for-field against the oracle
   (store count, GUID, volume size, creation FILETIME, shadow-copy IDs) — commit
   `37e552e` ("Tier-1 oracle — validate vsc-core vs pyvshadow on PC-MUS-001.E01").
3. **Open the E01 via the fleet `ewf` crate** as a dev-dependency
   (`core/Cargo.toml` `[dev-dependencies] ewf = "0.4"`), rather than reimplement
   E01 parsing — the fleet reuse-first rule, and the abstraction that lets the
   test read a real image.
4. **Reconstruction is oracle-checked too:** `tests/oracle/reconstruction_oracle.json`
   holds the pyvshadow-derived SHA-256 of the reconstructed block at
   representative offsets across all four paths; `sha2` (RustCrypto) hashes each
   reconstructed block for comparison (`core/Cargo.toml` dev-dep). Validated over
   1,415 blocks (ADR 0006).
5. **Tests are env-gated on the image path** (`oracle_pcmus001` /
   `reconstruct_pcmus001` in `core/tests/`, gated on `VSC_ORACLE_IMAGE`), so CI
   and fresh clones skip cleanly when the large artifact is absent — per the
   fleet test-data-provenance standard. Provenance is documented in
   `tests/data/README.md`.

## Consequences

- The correctness claim is tier-1 (independent authoring of both artifact and
  answer key on real data), not tier-3 — the README's "proven against an
  independent third-party oracle" is earned, not self-graded.
- The large E01 is never committed; it is downloaded manually and the tests read
  it in place, env-gated, so the repo stays small and CI stays green without it.
- A `docs/validation.md` is the canonical home the fleet expects for this
  evidence; today the write-up lives in `docs/RECONSTRUCTION.md` +
  `tests/data/README.md` + the README "Trust but verify" section. Consolidating
  it under `docs/validation.md` is a documented follow-up, not a correctness gap.
- Reusing `ewf` couples the test (not the shipped crate) to a fleet reader; the
  library itself remains container-agnostic (it takes any `Read + Seek`).
